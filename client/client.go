package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	//"syscall" // for RawConn in ListenConfig.Control

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth/oidc"
	client_config "github.com/francoismichel/ssh3/client/config"
	"github.com/francoismichel/ssh3/client/winsize"
	"github.com/francoismichel/ssh3/internal"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

type ExitStatus struct {
	StatusCode int
}

func (e ExitStatus) Error() string {
	return fmt.Sprintf("exited with status %d", e.StatusCode)
}

type ExitSignal struct {
	Signal           string
	ErrorMessageUTF8 string
}

func (e ExitSignal) Error() string {
	return fmt.Sprintf("exited with signal %s: %s", e.Signal, e.ErrorMessageUTF8)
}

type NoSuitableIdentity struct{}

func (e NoSuitableIdentity) Error() string {
	return "no suitable identity found"
}

func forwardAgent(parent context.Context, channel ssh3.Channel) error {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return fmt.Errorf("no auth socket in SSH_AUTH_SOCK env var")
	}
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithCancelCause(parent)
	go func() {
		var err error = nil
		var genericMessage ssh3Messages.Message
		for {
			select {
			case <-ctx.Done():
				err = context.Cause(ctx)
				if err != nil {
					log.Error().Msgf("reading message stopped on channel %d: %s", channel.ChannelID(), err.Error())
				}
				return
			default:
				genericMessage, err = channel.NextMessage()
				if err != nil && err != io.EOF {
					err = fmt.Errorf("error when getting message on channel %d: %s", channel.ChannelID(), err.Error())
					cancel(err)
					return
				}
				if genericMessage == nil {
					return
				}
				switch message := genericMessage.(type) {
				case *ssh3Messages.DataOrExtendedDataMessage:
					_, err = c.Write([]byte(message.Data))
					if err != nil {
						err = fmt.Errorf("error when writing on unix socker for agent forwarding channel %d: %s", channel.ChannelID(), err.Error())
						cancel(err)
						return
					}
				default:
					err = fmt.Errorf("unhandled message type on agent channel %d: %T", channel.ChannelID(), message)
					cancel(err)
					return
				}
			}
		}
	}()

	buf := make([]byte, channel.MaxPacketSize())
	for {
		select {
		case <-ctx.Done():
			err = context.Cause(ctx)
			if err != nil {
				log.Error().Msgf("ending agent forwarding on channel %d: %s", channel.ChannelID(), err.Error())
			}
			return err
		default:
			n, err := c.Read(buf)
			if err == io.EOF {
				log.Debug().Msgf("unix socket for ssh agent closed")
				return nil
			} else if err != nil {
				cancel(err)
				log.Error().Msgf("could not read on unix socket: %s", err.Error())
				return err
			}
			_, err = channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err != nil {
				cancel(err)
				log.Error().Msgf("could not write on ssh channel: %s", err.Error())
				return err
			}
		}
	}
}

func forwardTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
	go func() {
		defer conn.CloseWrite()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := channel.NextMessage()
			if err == io.EOF {
				log.Info().Msgf("eof on tcp-forwarding channel %d", channel.ChannelID())
			} else if err != nil {
				log.Error().Msgf("could get message from tcp forwarding channel: %s", err)
				return
			}

			// nothing to process
			if genericMessage == nil {
				return
			}

			switch message := genericMessage.(type) {
			case *ssh3Messages.DataOrExtendedDataMessage:
				if message.DataType == ssh3Messages.SSH_EXTENDED_DATA_NONE {
					_, err := conn.Write([]byte(message.Data))
					if err != nil {
						log.Error().Msgf("could not write data on TCP socket: %s", err)
						// signal the write error to the peer
						channel.CancelRead()
						return
					}
				} else {
					log.Warn().Msgf("ignoring message data of unexpected type %d on TCP forwarding channel %d", message.DataType, channel.ChannelID())
				}
			default:
				log.Warn().Msgf("ignoring message of type %T on TCP forwarding channel %d", message, channel.ChannelID())
			}
		}
	}()

	go func() {
		defer channel.Close()
		defer conn.CloseRead()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket: %s", errWrite)
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
			if err == io.EOF {
				return
			}
		}
	}()
}

func forwardReverseTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
	go func() {
		defer conn.CloseWrite()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := channel.NextMessage()
			if err == io.EOF {
				log.Info().Msgf("eof on tcp-forwarding channel %d", channel.ChannelID())
			} else if err != nil {
				log.Error().Msgf("could get message from tcp forwarding channel: %s", err)
				return
			}

			// nothing to process
			if genericMessage == nil {
				return
			}

			switch message := genericMessage.(type) {
			case *ssh3Messages.DataOrExtendedDataMessage:
				if message.DataType == ssh3Messages.SSH_EXTENDED_DATA_NONE {
					_, err := conn.Write([]byte(message.Data))
					if err != nil {
						log.Error().Msgf("could not write data on TCP socket: %s", err)
						// signal the write error to the peer
						channel.CancelRead()
						return
					}
				} else {
					log.Warn().Msgf("ignoring message data of unexpected type %d on TCP forwarding channel %d", message.DataType, channel.ChannelID())
				}
			default:
				log.Warn().Msgf("ignoring message of type %T on TCP forwarding channel %d", message, channel.ChannelID())
			}
		}
	}()

	go func() {
		defer channel.Close()
		defer conn.CloseRead()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			//log.Debug().Msgf("Reading from socket: %s", string(buf))
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket: %s", errWrite)
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
			if err == io.EOF {
				return
			}
		}
	}()
}

func forwardReverseUDPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.UDPConn) {
	go func() {
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			datagram, err := channel.ReceiveDatagram(ctx)
			if err != nil {
				log.Error().Msgf("could not receive datagram: %s", err)
				return
			}
			_, err = conn.Write(datagram)
			if err != nil {
				log.Error().Msgf("could not write datagram on UDP socket: %s", err)
				return
			}
		}
	}()

	go func() {
		defer channel.Close()
		defer conn.Close()
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil {
				log.Error().Msgf("could read datagram on UDP socket: %s", err)
				return
			}
			err = channel.SendDatagram(buf[:n])
			if err != nil {
				log.Error().Msgf("could send datagram on channel: %s", err)
				return
			}
		}
	}()
}

type Client struct {
	qconn quic.EarlyConnection
	*ssh3.Conversation

	// reverseDispatcher centralises the handling of all server-initiated
	// channels (open-request-reverse-{tcp,udp} and agent-connection)
	// arriving on this conversation, so there is exactly one consumer of
	// Conversation.AcceptChannel.  Previously every Reverse{TCP,UDP}
	// call started its own competing accept goroutine, and they raced
	// for incoming channels - any goroutine could grab a channel meant
	// for any of the configured reverse forwards and dial the wrong
	// destination.  Routing by the bind address embedded in the channel
	// header (see Conversation.OpenTCPReverseForwardingChannel and the
	// UDP variant) makes the wiring deterministic.
	reverseDispatcher *reverseDispatcher
}

// reverseDispatcher routes server-initiated data channels to the right
// handler.  Reverse-forwards register themselves keyed by their server-
// side bind address; the agent-forwarding setup registers a single
// "agent-connection" handler.  The dispatcher goroutine is started
// lazily by start() on first registration so a session that uses no
// reverse forwards and no agent forwarding does not pay for it.
type reverseDispatcher struct {
	mu          sync.Mutex
	tcpHandlers map[string]reverseTCPHandler // key = server-side bind addr (TCPAddr.String())
	udpHandlers map[string]reverseUDPHandler // key = server-side bind addr (UDPAddr.String())
	agentFn     func(channel ssh3.Channel)   // optional handler for "agent-connection" channels
	started     bool
}

type reverseTCPHandler struct {
	clientTarget *net.TCPAddr
	ctx          context.Context
}

type reverseUDPHandler struct {
	clientTarget *net.UDPAddr
	ctx          context.Context
}

func newReverseDispatcher() *reverseDispatcher {
	return &reverseDispatcher{
		tcpHandlers: make(map[string]reverseTCPHandler),
		udpHandlers: make(map[string]reverseUDPHandler),
	}
}

// registerTCP records the local target a reverse-TCP forward should dial
// when the server reports a new incoming connection on bindAddr, and
// starts the dispatch loop if it is not running yet.  ctx scopes the
// per-connection forwarding goroutines spawned for this handler.
func (c *Client) registerReverseTCP(ctx context.Context, bindAddr *net.TCPAddr, clientTarget *net.TCPAddr) {
	c.reverseDispatcher.mu.Lock()
	c.reverseDispatcher.tcpHandlers[bindAddr.String()] = reverseTCPHandler{
		clientTarget: clientTarget,
		ctx:          ctx,
	}
	c.reverseDispatcher.startLocked(c)
	c.reverseDispatcher.mu.Unlock()
}

func (c *Client) registerReverseUDP(ctx context.Context, bindAddr *net.UDPAddr, clientTarget *net.UDPAddr) {
	c.reverseDispatcher.mu.Lock()
	c.reverseDispatcher.udpHandlers[bindAddr.String()] = reverseUDPHandler{
		clientTarget: clientTarget,
		ctx:          ctx,
	}
	c.reverseDispatcher.startLocked(c)
	c.reverseDispatcher.mu.Unlock()
}

// registerAgentForwarding records a handler for "agent-connection" channels.
// Setting it more than once overwrites the previous handler; in practice
// it is called at most once per session.
func (c *Client) registerAgentForwarding(handler func(channel ssh3.Channel)) {
	c.reverseDispatcher.mu.Lock()
	c.reverseDispatcher.agentFn = handler
	c.reverseDispatcher.startLocked(c)
	c.reverseDispatcher.mu.Unlock()
}

// startLocked starts the dispatch goroutine the first time any handler is
// registered.  Caller must hold reverseDispatcher.mu.
func (d *reverseDispatcher) startLocked(c *Client) {
	if d.started {
		return
	}
	d.started = true
	go d.run(c)
}

func (d *reverseDispatcher) run(c *Client) {
	for {
		channel, err := c.AcceptChannel(c.Context())
		if err != nil {
			// Conversation cancelled/closed: stop.  At debug level
			// because this is the normal teardown path.
			log.Debug().Msgf("reverse-channel dispatcher exiting: %s", err)
			return
		}
		d.dispatch(channel)
	}
}

func (d *reverseDispatcher) dispatch(channel ssh3.Channel) {
	switch c := channel.(type) {
	case *ssh3.TCPOpenReverseForwardingChannelImpl:
		if c.BindAddr == nil {
			log.Error().Msgf("open-request-reverse-tcp channel %d arrived without a bind address; closing", channel.ChannelID())
			channel.Close()
			return
		}
		d.mu.Lock()
		h, ok := d.tcpHandlers[c.BindAddr.String()]
		d.mu.Unlock()
		if !ok {
			log.Error().Msgf("no reverse-TCP handler registered for bind %s; closing channel %d", c.BindAddr, channel.ChannelID())
			channel.Close()
			return
		}
		log.Debug().Msgf("reverse TCP: server bind %s -> dialing client target %s", c.BindAddr, h.clientTarget)
		conn, err := net.DialTCP("tcp", nil, h.clientTarget)
		if err != nil {
			log.Error().Msgf("reverse TCP: could not dial client target %s: %s", h.clientTarget, err)
			channel.Close()
			return
		}
		forwardReverseTCPInBackground(h.ctx, channel, conn)

	case *ssh3.UDPOpenReverseForwardingChannelImpl:
		if c.BindAddr == nil {
			log.Error().Msgf("open-request-reverse-udp channel %d arrived without a bind address; closing", channel.ChannelID())
			channel.Close()
			return
		}
		d.mu.Lock()
		h, ok := d.udpHandlers[c.BindAddr.String()]
		d.mu.Unlock()
		if !ok {
			log.Error().Msgf("no reverse-UDP handler registered for bind %s; closing channel %d", c.BindAddr, channel.ChannelID())
			channel.Close()
			return
		}
		log.Debug().Msgf("reverse UDP: server bind %s -> dialing client target %s", c.BindAddr, h.clientTarget)
		conn, err := net.DialUDP("udp", nil, h.clientTarget)
		if err != nil {
			log.Error().Msgf("reverse UDP: could not dial client target %s: %s", h.clientTarget, err)
			channel.Close()
			return
		}
		forwardReverseUDPInBackground(h.ctx, channel, conn)

	default:
		// Generic channel: only "agent-connection" is currently
		// expected through this path.  Anything else is an
		// unsolicited channel we have no policy for.
		if channel.ChannelType() == "agent-connection" {
			d.mu.Lock()
			fn := d.agentFn
			d.mu.Unlock()
			if fn == nil {
				log.Warn().Msgf("received agent-connection channel %d but agent forwarding is not registered; closing", channel.ChannelID())
				channel.Close()
				return
			}
			fn(channel)
			return
		}
		log.Warn().Msgf("closing unsolicited channel type %q (id %d)", channel.ChannelType(), channel.ChannelID())
		channel.Close()
	}
}

func Dial(ctx context.Context, config *client_config.Config, qconn quic.EarlyConnection,
	roundTripper *http3.RoundTripper,
	sshAgent agent.ExtendedAgent) (*Client, error) {

	hostUrl := url.URL{}
	hostUrl.Scheme = "https"
	hostUrl.Host = config.URLHostnamePort()
	hostUrl.Path = config.UrlPath()
	urlQuery := hostUrl.Query()
	urlQuery.Set("user", config.Username())
	hostUrl.RawQuery = urlQuery.Encode()
	requestUrl := hostUrl.String()

	var qconf quic.Config

	qconf.MaxIncomingUniStreams = 10000
	qconf.MaxIncomingStreams = 10000
	qconf.Allow0RTT = false
	qconf.EnableDatagrams = true
	qconf.KeepAlivePeriod = 1 * time.Second

	var agentKeys []ssh.PublicKey
	if sshAgent != nil {
		keys, err := sshAgent.List()
		if err != nil {
			log.Error().Msgf("Failed to list agent keys: %s", err)
			return nil, err
		}
		for _, key := range keys {
			agentKeys = append(agentKeys, key)
		}
	}

	// dirty hack: ensure only one QUIC connection is used
	roundTripper.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		return qconn, nil
	}

	// Do 0RTT GET requests here if needed
	// Currently, we don't need it but we could use it to retrieve
	// config or version info from the server
	// We could also allow user-defined safe/idempotent commands to run with 0-RTT
	qconn.HandshakeComplete()
	log.Debug().Msgf("QUIC handshake complete")
	// Now, we're 1-RTT, we can get the TLS exporter and create the conversation
	tls := qconn.ConnectionState().TLS
	conv, err := ssh3.NewClientConversation(30000, 10, &tls)
	if err != nil {
		return nil, err
	}

	// the connection struct is created, now build the request used to establish the connection
	req, err := http.NewRequest("CONNECT", requestUrl, nil)
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}
	req.Proto = "ssh3"

	// TODO: replace this by a loop actually performing the requests for qeach auth method of each plugin
	foundSuitableAuthPlugin := false
	plugins := internal.GetClientAuthPlugins()
	for _, plugin := range plugins {
		authMethods, err := plugin.PluginFunc(req, sshAgent, config, roundTripper)
		if err != nil {
			return nil, err
		}
		for _, authMethod := range authMethods {
			err = authMethod.PrepareRequestForAuth(req, sshAgent, roundTripper, config.Username(), conv)
			if err != nil {
				log.Error().Msgf("error when preparing request for auth plugin %T: %s", plugin, err)
				return nil, err
			}
			foundSuitableAuthPlugin = true
			log.Debug().Msgf("found suitable auth plugin")
		}
	}

	if !foundSuitableAuthPlugin {

		var identity ssh3.Identity
		for _, method := range config.AuthMethods() {
			switch m := method.(type) {
			case *ssh3.PasswordAuthMethod:
				log.Debug().Msgf("try password-based auth")
				fmt.Printf("password for %s:", hostUrl.String())
				password, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					log.Error().Msgf("could not get password: %s", err)
					return nil, err
				}
				identity = m.IntoIdentity(string(password))
			case *ssh3.PrivkeyFileAuthMethod:
				log.Debug().Msgf("try file-based pubkey auth using file %s", m.Filename())
				identity, err = m.IntoIdentityWithoutPassphrase()
				// could not identify without passphrase, try agent authentication by using the key's public key
				if passphraseErr, ok := err.(*ssh.PassphraseMissingError); ok {
					// the pubkey may be contained in the privkey file
					pubkey := passphraseErr.PublicKey
					if pubkey == nil {
						// if it is not the case, try to find a .pub equivalent, like OpenSSH does
						pubkeyBytes, err := os.ReadFile(fmt.Sprintf("%s.pub", m.Filename()))
						if err == nil {
							filePubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
							if err == nil {
								pubkey = filePubkey
							}
						}
					}

					// now, try to see of the agent manages this key
					foundAgentKey := false
					if pubkey != nil {
						for _, agentKey := range agentKeys {
							if bytes.Equal(agentKey.Marshal(), pubkey.Marshal()) {
								log.Debug().Msgf("found key in agent: %s", agentKey)
								identity = ssh3.NewAgentAuthMethod(pubkey).IntoIdentity(sshAgent)
								foundAgentKey = true
								break
							}
						}
					}

					// key not handled by agent, let's try to decrypt it ourselves
					if !foundAgentKey {
						fmt.Printf("passphrase for private key stored in %s:", m.Filename())
						var passphraseBytes []byte
						passphraseBytes, err = term.ReadPassword(int(syscall.Stdin))
						fmt.Println()
						if err != nil {
							log.Error().Msgf("could not get passphrase: %s", err)
							return nil, err
						}
						passphrase := string(passphraseBytes)
						identity, err = m.IntoIdentityPassphrase(passphrase)
						if err != nil {
							log.Error().Msgf("could not load private key: %s", err)
							return nil, err
						}
					}
				} else if err != nil {
					log.Warn().Msgf("Could not load private key: %s", err)
				}
			case *ssh3.AgentAuthMethod:
				log.Debug().Msgf("try ssh-agent-based auth")
				identity = m.IntoIdentity(sshAgent)
			case *ssh3.OidcAuthMethod:
				log.Debug().Msgf("try OIDC auth to issuer %s", m.OIDCConfig().IssuerUrl)
				token, err := oidc.Connect(context.Background(), m.OIDCConfig(), m.OIDCConfig().IssuerUrl, m.DoPKCE())
				if err != nil {
					log.Error().Msgf("could not get token: %s", err)
					return nil, err
				}
				identity = m.IntoIdentity(token)
			}
			// currently only tries a single identity (the first one), but the goal is to
			// try several identities, similarly to OpenSSH
			log.Debug().Msgf("we only try the first specified auth method for now")
			break
		}

		if identity == nil {
			return nil, NoSuitableIdentity{}
		}

		log.Debug().Msgf("try the following Identity: %s", identity)
		err = identity.SetAuthorizationHeader(req, config.Username(), conv)
		if err != nil {
			log.Error().Msgf("could not set authorization header in HTTP request: %s", err)
			return nil, err
		}
	}

	log.Debug().Msgf("establish conversation with the server")
	err = conv.EstablishClientConversation(req, roundTripper, ssh3.AVAILABLE_CLIENT_VERSIONS)
	if errors.Is(err, util.Unauthorized{}) {
		log.Error().Msgf("Access denied from the server: unauthorized")
		return nil, err
	} else if err != nil {
		log.Error().Msgf("Could not establish conversation: %+v", err)
		return nil, err
	}

	return &Client{
		qconn:             qconn,
		Conversation:      conv,
		reverseDispatcher: newReverseDispatcher(),
	}, nil
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Functions below should be included in a package to avoid reusing them aswell in client.go

func ListenUDPReuse(ctx context.Context, network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(netw, addr string, c syscall.RawConn) error {
			var firstErr error
			c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil && firstErr == nil {
					firstErr = fmt.Errorf("SO_REUSEADDR: %w", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil && firstErr == nil {
					firstErr = fmt.Errorf("SO_REUSEPORT: %w", err)
				}
			})
			return firstErr
		},
	}

	pc, err := lc.ListenPacket(ctx, network, laddr.String()) // "udp", "udp4", or "udp6"
	if err != nil {
		return nil, err
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("not a UDP socket")
	}
	return uc, nil
}


func disableMulticastAll(uc *net.UDPConn) error {
    rc, err := uc.SyscallConn()
    if err != nil {
        return err
    }
    var serr error
    err = rc.Control(func(fd uintptr) {
        // IP_MULTICAST_ALL = 49 on Linux; use unix.IP_MULTICAST_ALL for portability.
        if e := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); e != nil {
            serr = e
        }
    })
    if err != nil {
        return err
    }
    return serr
}

// ListenUDPWithAutoMulticast listens on udpAddr.  For a non-multicast
// destination it is a thin wrapper over net.ListenUDP in the right address
// family.  For a multicast group it always opens a fresh socket (bound to
// the wildcard address in the right family with SO_REUSEADDR/REUSEPORT),
// disables IP_MULTICAST_ALL on Linux and joins the group on every
// up/multicast-capable interface, or on the named interface if ifaceName
// is non-empty.
func ListenUDPWithAutoMulticast(udpAddr *net.UDPAddr, ifaceName string) (*net.UDPConn, error) {
	if udpAddr == nil {
		return nil, fmt.Errorf("nil UDPAddr")
	}
	isV4 := udpAddr.IP.To4() != nil

	// Non-multicast or unspecified: plain listen in the right family.
	if udpAddr.IP == nil || !udpAddr.IP.IsMulticast() {
		network := "udp"
		if isV4 {
			network = "udp4"
		} else {
			network = "udp6"
		}
		return net.ListenUDP(network, udpAddr)
	}

	// Multicast: bind to wildcard in the right family.  We must always
	// open a fresh socket here; sharing a socket across distinct group
	// memberships defeats per-group join semantics on Linux.
	var bind *net.UDPAddr
	var network string
	if isV4 {
		bind = &net.UDPAddr{IP: net.IPv4zero, Port: udpAddr.Port}
		network = "udp4"
	} else {
		bind = &net.UDPAddr{IP: net.IPv6unspecified, Port: udpAddr.Port}
		network = "udp6"
	}

	conn, err := ListenUDPReuse(context.Background(), network, bind)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	// Linux: ensure we only receive groups we actually join.
	if err := disableMulticastAll(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("disableMulticastAll: %w", err)
	}

	// Join group (same join helpers as before)
	if isV4 {
		p := ipv4.NewPacketConn(conn)
		if err := joinOnInterfacesV4(p, udpAddr, ifaceName); err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		p := ipv6.NewPacketConn(conn)
		if err := joinOnInterfacesV6(p, udpAddr, ifaceName); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func joinOnInterfacesV4(p *ipv4.PacketConn, group *net.UDPAddr, ifaceName string) error {
	if ifaceName != "" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("iface '%s': %w", ifaceName, err)
		}
		return p.JoinGroup(ifi, &net.UDPAddr{IP: group.IP})
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list ifaces: %w", err)
	}

	var errs []string
	joined := 0
	for _, ifi := range ifaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagMulticast) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		if err := p.JoinGroup(&ifi, &net.UDPAddr{IP: group.IP}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ifi.Name, err))
			continue
		}
		joined++
	}
	if joined == 0 {
		if len(errs) > 0 {
			return errors.New("failed to join on any iface: " + strings.Join(errs, "; "))
		}
		return errors.New("no suitable interfaces found to join multicast")
	}
	return nil
}


func joinOnInterfacesV6(p *ipv6.PacketConn, group *net.UDPAddr, ifaceName string) error {
	if ifaceName != "" {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("iface '%s': %w", ifaceName, err)
		}
		return p.JoinGroup(ifi, &net.UDPAddr{IP: group.IP})
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list ifaces: %w", err)
	}

	var errs []string
	joined := 0
	for _, ifi := range ifaces {
		if (ifi.Flags&net.FlagUp) == 0 || (ifi.Flags&net.FlagMulticast) == 0 || (ifi.Flags&net.FlagLoopback) != 0 {
			continue
		}
		if err := p.JoinGroup(&ifi, &net.UDPAddr{IP: group.IP}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ifi.Name, err))
			continue
		}
		joined++
	}
	if joined == 0 {
		if len(errs) > 0 {
			return errors.New("failed to join on any iface: " + strings.Join(errs, "; "))
		}
		return errors.New("no suitable interfaces found to join multicast")
	}
	return nil
}
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



func (c *Client) ForwardUDP(ctx context.Context, localUDPAddr *net.UDPAddr, remoteUDPAddr *net.UDPAddr) (*net.UDPAddr, error) {
	log.Debug().Msgf("start UDP forwarding from %s to %s", localUDPAddr, remoteUDPAddr)
	conn, err := ListenUDPWithAutoMulticast(localUDPAddr, "")
	if err != nil {
		log.Error().Msgf("could not listen on UDP socket: %s", err)
		return nil, err
	}
    // Close everything when ctx is canceled.

	forwardings := make(map[string]ssh3.Channel)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Error().Msgf("could not read on UDP socket: %s", err)
				return
			}
			channel, ok := forwardings[addr.String()]
			if !ok {
				channel, err = c.OpenUDPForwardingChannel(30000, 10, localUDPAddr, remoteUDPAddr)
				if err != nil {
					log.Error().Msgf("could open new UDP forwarding channel: %s", err)
					return
				}
				forwardings[addr.String()] = channel

				go func() {
					for {
						dgram, err := channel.ReceiveDatagram(ctx)
						if err != nil {
							log.Error().Msgf("could open receive datagram on channel: %s", err)
							return
						}
						_, err = conn.WriteToUDP(dgram, addr)
						if err != nil {
							log.Error().Msgf("could open write datagram on socket: %s", err)
							return
						}
					}
				}()
			}
			err = channel.SendDatagram(buf[:n])
			if err != nil {
				log.Error().Msgf("could not send datagram: %s", err)
				return
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), nil
}

func (c *Client) ForwardTCP(ctx context.Context, localTCPAddr *net.TCPAddr, remoteTCPAddr *net.TCPAddr) (*net.TCPAddr, error) {
	log.Debug().Msgf("start TCP forwarding from %s to %s", localTCPAddr, remoteTCPAddr)
	conn, err := net.ListenTCP("tcp", localTCPAddr)
	if err != nil {
		log.Error().Msgf("could listen on TCP socket: %s", err)
		return nil, err
	}
	go func() {
		for {
			conn, err := conn.AcceptTCP()
			if err != nil {
				log.Error().Msgf("could read on UDP socket: %s", err)
				return
			}
			forwardingChannel, err := c.OpenTCPForwardingChannel(30000, 10, localTCPAddr, remoteTCPAddr)
			if err != nil {
				log.Error().Msgf("could open new UDP forwarding channel: %s", err)
				return
			}
			forwardTCPInBackground(ctx, forwardingChannel, conn)
		}
	}()
	return conn.Addr().(*net.TCPAddr), nil
}

// readReverseSetupAck waits up to `timeout` for the server to write a single
// setup-acknowledgement message on a request-reverse-{tcp,udp} channel (see
// ssh3.ReverseSetupAck{OK,Fail}).  The caller is responsible for closing the
// channel afterwards regardless of the outcome.
//
// Return values:
//   - ok=true                          listener was opened on the server.
//   - ok=false, err!=nil               server reported a failure (with the
//                                      reason string it sent), or sent
//                                      data we cannot interpret as part of
//                                      this protocol (likely version skew
//                                      or corruption).
//   - ok=false, err==nil, legacy=true  the peer never sent any setup data
//                                      (read timeout, or EOF before any
//                                      bytes).  Assume a server that
//                                      predates this handshake.
//
// Anything *other* than "no data at all" is treated as a real signal:
// either a known ack or a protocol error.  Silently ignoring unknown
// opcodes here would defeat the whole point of the handshake.
func readReverseSetupAck(channel ssh3.Channel, timeout time.Duration) (ok bool, legacy bool, err error) {
	type readResult struct {
		msg ssh3Messages.Message
		err error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		msg, e := channel.NextMessage()
		resultCh <- readResult{msg, e}
	}()
	select {
	case r := <-resultCh:
		if r.err != nil {
			// EOF without any data means the peer closed the channel
			// without acking - most likely a legacy server.
			if errors.Is(r.err, io.EOF) {
				return false, true, nil
			}
			return false, false, r.err
		}
		dm, isData := r.msg.(*ssh3Messages.DataOrExtendedDataMessage)
		if !isData {
			return false, false, fmt.Errorf("unexpected %T on reverse-forward setup channel", r.msg)
		}
		if dm.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
			return false, false, fmt.Errorf("unexpected extended-data type %d on reverse-forward setup channel", dm.DataType)
		}
		if len(dm.Data) == 0 {
			return false, false, fmt.Errorf("empty reverse-forward setup message")
		}
		switch dm.Data[0] {
		case ssh3.ReverseSetupAckOK:
			return true, false, nil
		case ssh3.ReverseSetupAckFail:
			reason := strings.TrimSpace(dm.Data[1:])
			if reason == "" {
				reason = "server reported failure with no reason"
			}
			return false, false, fmt.Errorf("%s", reason)
		default:
			return false, false, fmt.Errorf("unknown reverse-forward setup opcode 0x%02x", dm.Data[0])
		}
	case <-time.After(timeout):
		channel.CancelRead()
		return false, true, nil
	}
}

// ReverseTCP sets up an SSH-style reverse TCP port forward.
//
// The "client-local" half (clientTargetAddr) is the address on the client side
// to which incoming forwarded connections will be relayed (analogous to the
// HOST:HOSTPORT in OpenSSH's "-R bind:port:HOST:HOSTPORT").
//
// The "server-side" half (serverBindAddr) is the address on the server side
// where the listening socket is opened (analogous to the bind:port half).
//
// Wire-protocol note: the underlying channel header carries the server-bind
// address in the "local" slot and the client-target address in the "remote"
// slot (see server.go: TCPReverseForwardingChannelImpl, where LocalAddr is the
// socket on the server machine and RemoteAddr is the socket reached via the
// client). RequestTCPReverseChannel forwards its (localAddr, remoteAddr)
// arguments to that header in that order, so we pass serverBindAddr first.
//
// After sending the request, ReverseTCP waits for a setup acknowledgement
// from the server (see readReverseSetupAck) and, if the server reports a
// failure (e.g. the bind port is already in use), returns that error so the
// caller can abort - this matches OpenSSH's ExitOnForwardFailure semantics.
//
// On success the per-connection data channels the server opens for this
// forward are routed by the central reverseDispatcher, which keys on the
// bind address embedded in each open-request-reverse-tcp channel header
// (see Conversation.OpenTCPReverseForwardingChannel).  That makes
// multiple concurrent reverse-TCP forwards on the same conversation
// deterministic instead of letting per-forward accept goroutines race.
func (c *Client) ReverseTCP(ctx context.Context, clientTargetAddr *net.TCPAddr, serverBindAddr *net.TCPAddr) (*net.TCPAddr, error) {
	log.Debug().Msgf("request reverse TCP forwarding: server bind %s -> client target %s", serverBindAddr, clientTargetAddr)

	forwardingChannel, err := c.RequestTCPReverseChannel(30000, 10, serverBindAddr, clientTargetAddr)
	if err != nil {
		log.Error().Msgf("could not open new TCP reverse forwarding channel: %s", err)
		return serverBindAddr, err
	}

	ok, legacy, ackErr := readReverseSetupAck(forwardingChannel, 5*time.Second)
	if ackErr != nil {
		forwardingChannel.Close()
		return serverBindAddr, fmt.Errorf("server refused reverse TCP %s -> %s: %s", serverBindAddr, clientTargetAddr, ackErr)
	}
	if legacy {
		log.Warn().Msgf("server did not acknowledge reverse TCP setup for %s within timeout; assuming legacy server (forwarding may silently fail)", serverBindAddr)
	} else if ok {
		log.Debug().Msgf("server acknowledged reverse TCP setup on %s", serverBindAddr)
	}

	// Hand the per-connection routing off to the central dispatcher and
	// release the request channel; further work on this forward happens
	// asynchronously each time the server opens a new data channel.
	c.registerReverseTCP(ctx, serverBindAddr, clientTargetAddr)
	forwardingChannel.Close()
	return serverBindAddr, nil
}

// ReverseUDP sets up an SSH-style reverse UDP port forward.
// See ReverseTCP for the meaning of clientTargetAddr and serverBindAddr,
// for the server-side setup-failure handshake, and for how per-connection
// data channels are routed via the central reverseDispatcher.
func (c *Client) ReverseUDP(ctx context.Context, clientTargetAddr *net.UDPAddr, serverBindAddr *net.UDPAddr) (*net.UDPAddr, error) {
	log.Debug().Msgf("request reverse UDP forwarding: server bind %s -> client target %s", serverBindAddr, clientTargetAddr)

	forwardingChannel, err := c.RequestUDPReverseChannel(30000, 10, serverBindAddr, clientTargetAddr)
	if err != nil {
		log.Error().Msgf("could not open new UDP reverse forwarding channel: %s", err)
		return serverBindAddr, err
	}

	ok, legacy, ackErr := readReverseSetupAck(forwardingChannel, 5*time.Second)
	if ackErr != nil {
		forwardingChannel.Close()
		return serverBindAddr, fmt.Errorf("server refused reverse UDP %s -> %s: %s", serverBindAddr, clientTargetAddr, ackErr)
	}
	if legacy {
		log.Warn().Msgf("server did not acknowledge reverse UDP setup for %s within timeout; assuming legacy server (forwarding may silently fail)", serverBindAddr)
	} else if ok {
		log.Debug().Msgf("server acknowledged reverse UDP setup on %s", serverBindAddr)
	}

	c.registerReverseUDP(ctx, serverBindAddr, clientTargetAddr)
	forwardingChannel.Close()
	return serverBindAddr, nil
}


func (c *Client) RunSession(tty *os.File, forwardSSHAgent bool, command ...string) error {

	ctx := c.Context()

	// All server-initiated channels - reverse-forward data channels and
	// agent-connection channels - flow through the central
	// reverseDispatcher (started lazily on first registration).  No
	// per-handler AcceptChannel goroutine is started here on purpose:
	// having two consumers on the same AcceptChannel queue caused the
	// reverse-forward race that this refactor exists to remove.

	channel, err := c.OpenChannel("session", 30000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open channel: %+v", err)
		os.Exit(-1)
	}

	log.Debug().Msgf("opened new session channel")

	if forwardSSHAgent {
		_, err := channel.WriteData([]byte("forward-agent"), ssh3Messages.SSH_EXTENDED_DATA_NONE)
		if err != nil {
			log.Error().Msgf("could not forward agent: %s", err.Error())
			return err
		}
		c.registerAgentForwarding(func(forwardChannel ssh3.Channel) {
			log.Debug().Msg("new agent connection, forwarding")
			go func() {
				if err := forwardAgent(ctx, forwardChannel); err != nil {
					log.Error().Msgf("agent forwarding error: %s", err.Error())
					c.Close()
				}
			}()
		})
	}

	if len(command) == 0 {
		// avoid requesting a pty on the other side if stdin is not a pty
		// similar behaviour to OpenSSH
		isATTY := term.IsTerminal(int(tty.Fd()))

		windowSize, err := winsize.GetWinsize(tty)
		if err != nil {
			log.Warn().Msgf("could not get window size: %+v", err)
		}
		hasWinSize := err == nil
		if isATTY && hasWinSize {
			err = channel.SendRequest(
				&ssh3Messages.ChannelRequestMessage{
					WantReply: true,
					ChannelRequest: &ssh3Messages.PtyRequest{
						Term:        os.Getenv("TERM"),
						CharWidth:   uint64(windowSize.NCols),
						CharHeight:  uint64(windowSize.NRows),
						PixelWidth:  uint64(windowSize.PixelWidth),
						PixelHeight: uint64(windowSize.PixelHeight),
					},
				},
			)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Could send pty request: %+v", err)
				return err
			}
			log.Debug().Msgf("sent pty request for session")
		}

		err = channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply:      true,
				ChannelRequest: &ssh3Messages.ShellRequest{},
			},
		)
		if err != nil {
			log.Error().Msgf("could not send shell request: %s", err)
			return err
		}
		log.Debug().Msgf("sent shell request, hasWinSize = %t", hasWinSize)
		// avoid making the terminal raw if stdin is not a TTY
		// similar behaviour to OpenSSH
		if isATTY {
			fd := os.Stdin.Fd()
			oldState, err := term.MakeRaw(int(fd))
			if err != nil {
				log.Warn().Msgf("cannot make tty raw: %s", err)
			} else {
				defer term.Restore(int(fd), oldState)
			}
		}
	} else {
		channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply: true,
				ChannelRequest: &ssh3Messages.ExecRequest{
					Command: strings.Join(command, " "),
				},
			},
		)
		log.Debug().Msgf("sent exec request for command \"%s\"", strings.Join(command, " "))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could send shell request: %+v", err)
		return err
	}

	go func() {
		buf := make([]byte, channel.MaxPacketSize())
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				_, err2 := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
				if err2 != nil {
					fmt.Fprintf(os.Stderr, "could not write data on channel: %+v", err2)
					return
				}
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not read data from stdin: %+v", err)
				return
			}
		}
	}()

	defer fmt.Printf("\r")

	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not get message: %+v\n", err)
			os.Exit(-1)
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.ChannelRequestMessage:
			switch requestMessage := message.ChannelRequest.(type) {
			case *ssh3Messages.PtyRequest:
				fmt.Fprintf(os.Stderr, "receiving a pty request on the client is not implemented\n")
			case *ssh3Messages.X11Request:
				fmt.Fprintf(os.Stderr, "receiving a x11 request on the client is not implemented\n")
			case *ssh3Messages.ShellRequest:
				fmt.Fprintf(os.Stderr, "receiving a shell request on the client is not implemented\n")
			case *ssh3Messages.ExecRequest:
				fmt.Fprintf(os.Stderr, "receiving a exec request on the client is not implemented\n")
			case *ssh3Messages.SubsystemRequest:
				fmt.Fprintf(os.Stderr, "receiving a subsystem request on the client is not implemented\n")
			case *ssh3Messages.WindowChangeRequest:
				fmt.Fprintf(os.Stderr, "receiving a windowchange request on the client is not implemented\n")
			case *ssh3Messages.SignalRequest:
				fmt.Fprintf(os.Stderr, "receiving a signal request on the client is not implemented\n")
			case *ssh3Messages.ExitStatusRequest:
				log.Info().Msgf("ssh3: process exited with status: %d\n", requestMessage.ExitStatus)
				// forward the process' status code to the user
				return ExitStatus{StatusCode: int(requestMessage.ExitStatus)}
			case *ssh3Messages.ExitSignalRequest:
				log.Info().Msgf("ssh3: process exited with signal: %s: %s\n", requestMessage.SignalNameWithoutSig, requestMessage.ErrorMessageUTF8)
				return ExitSignal{Signal: requestMessage.SignalNameWithoutSig, ErrorMessageUTF8: requestMessage.ErrorMessageUTF8}
			}
		case *ssh3Messages.DataOrExtendedDataMessage:
			switch message.DataType {
			case ssh3Messages.SSH_EXTENDED_DATA_NONE:
				_, err = os.Stdout.Write([]byte(message.Data))
				if err != nil {
					log.Fatal().Msgf("%s", err)
				}

				log.Trace().Msgf("received data %s", message.Data)
			case ssh3Messages.SSH_EXTENDED_DATA_STDERR:
				_, err = os.Stderr.Write([]byte(message.Data))
				if err != nil {
					log.Fatal().Msgf("%s", err)
				}

				log.Trace().Msgf("received stderr data %s", message.Data)
			}
		}
	}
}
