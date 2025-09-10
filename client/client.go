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
	"syscall"
	"time"

	"encoding/binary"

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
		qconn:        qconn,
		Conversation: conv,
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

// ListenUDPWithAutoMulticast listens on udpAddr.
// If udpAddr.IP is multicast, it binds to the wildcard address on the same
// family+port and joins the multicast group. Otherwise it just listens normally.
//
// If ifaceName is non-empty, it will join only on that interface.
// Otherwise it tries all "up" multicast-capable interfaces (excluding loopback).
func ListenUDPWithAutoMulticast(udpAddr *net.UDPAddr, ifaceName string, conn *net.UDPConn ) (*net.UDPConn, error) {
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

	// Multicast: bind to wildcard in the right family.
	var bind *net.UDPAddr
	var network string
	if isV4 {
		bind = &net.UDPAddr{IP: net.IPv4zero, Port: udpAddr.Port}
		network = "udp4"
	} else {
		bind = &net.UDPAddr{IP: net.IPv6unspecified, Port: udpAddr.Port}
		network = "udp6"
	}

	var err error
	conn = nil
	//It must be always a new connection. Otherwise, we are not subscribing correctly.
	if conn == nil {
		//conn, err = net.ListenUDP(network, bind)
		conn, err = ListenUDPReuse(context.Background(), network, bind)		
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		// Linux: ensure we only receive groups we actually join.
		if err := disableMulticastAll(conn); err != nil {
			// consider returning the error; otherwise log loudly
			return nil, fmt.Errorf("disableMulticastAll: %w", err)
		}
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



func (c *Client) ForwardUDP(ctx context.Context, localUDPAddr *net.UDPAddr, remoteUDPAddr *net.UDPAddr, multconn *net.UDPConn) (*net.UDPAddr, *net.UDPConn, error) {
	log.Debug().Msgf("start UDP forwarding from %s to %s", localUDPAddr, remoteUDPAddr)
	//conn, err := net.ListenUDP("udp", localUDPAddr)
	conn, err := ListenUDPWithAutoMulticast(localUDPAddr,"",multconn)
	if err != nil {
		log.Error().Msgf("could not listen on UDP socket: %s", err)
		return nil, nil, err
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
	return conn.LocalAddr().(*net.UDPAddr), conn, nil
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

func (c *Client) ReverseTCP(ctx context.Context, localTCPAddr *net.TCPAddr, remoteTCPAddr *net.TCPAddr) (*net.TCPAddr, error) {
	log.Debug().Msgf("start TCP forwarding from %s to %s", localTCPAddr, remoteTCPAddr)

	forwardingChannel, err := c.RequestTCPReverseChannel(30000, 10, localTCPAddr, remoteTCPAddr)
	if err != nil {
		log.Error().Msgf("could open new TCP reverse forwarding channel: %s", err)
		return remoteTCPAddr, nil
	}

	go func() {
		for {
			channel, err := c.AcceptChannel(c.Context())
			if err != nil {
				log.Debug().Msgf("Error accepting channel")
			}

			switch channel.ChannelType() {
			case "open-request-reverse-tcp":
				log.Debug().Msgf("start reverse TCP forwarding from %s to %s", localTCPAddr, remoteTCPAddr)

				conn, err := net.DialTCP("tcp", nil, remoteTCPAddr)
				if err != nil {
					return
				}
				forwardReverseTCPInBackground(ctx, channel, conn)
				if err != nil {
					channel.Close()
					return
				}
			}
		}
	}()
	forwardingChannel.Close()
	return remoteTCPAddr, nil
}

func (c *Client) ReverseUDP(ctx context.Context, localUDPAddr *net.UDPAddr, remoteUDPAddr *net.UDPAddr) (*net.UDPAddr, error) {
	log.Debug().Msgf("start UDP reverse forwarding from %s to %s", localUDPAddr, remoteUDPAddr)

	forwardingChannel, err := c.RequestUDPReverseChannel(30000, 10, localUDPAddr, remoteUDPAddr)
	if err != nil {
		log.Error().Msgf("could open new UDP reverse forwarding channel: %s", err)
		return remoteUDPAddr, nil
	}
	forwardingChannel.Close()
	return remoteUDPAddr, nil
}


func parseAddrsFromChannelType(typ string) (*net.UDPAddr, *net.UDPAddr, error) {
	// Prefer HasPrefix to avoid accidental matches.


	parts := strings.SplitN(typ, ",", 3)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("bad format (want: open-request-reverse-udp,<local>,<remote>): %q", typ)
	}

	localStr := strings.TrimSpace(parts[1])
	remoteStr := strings.TrimSpace(parts[2])

	// Accept IPv4 or IPv6 (IPv6 with port must be in [addr]:port form).
	localUDPAddr, err := net.ResolveUDPAddr("udp", localStr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local UDP addr %q: %w", localStr, err)
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", remoteStr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse remote UDP addr %q: %w", remoteStr, err)
	}

	return localUDPAddr, remoteUDPAddr, nil
}

func parseUDPRequestReverseHeader(channelID uint64, buf util.Reader) (*net.UDPAddr, *net.UDPAddr, error) {
	localaddress, localport, remoteaddress, remoteport, err := parseRequestReverseHeader(channelID, buf)
	if err != nil {
		return nil, nil, err
	}
	return &net.UDPAddr{
			IP:   localaddress,
			Port: int(localport),
		}, &net.UDPAddr{
			IP:   remoteaddress,
			Port: int(remoteport),
		}, nil
}

func parseRequestReverseHeader(channelID uint64, buf util.Reader) (net.IP, uint16, net.IP, uint16, error) {

	var localaddress net.IP
	var remoteaddress net.IP
	var portBuf [2]byte

	//Parse local address and port where the reverse socket is proxied within the client machine
	//------------------------------------------------------------------------------------------
	addressFamily, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, 0, nil, 0, err
	}

	if addressFamily == util.SSHAFIpv4 {
		localaddress = make([]byte, 4)
	} else if addressFamily == util.SSHAFIpv6 {
		localaddress = make([]byte, 16)
	} else {
		return nil, 0, nil, 0, fmt.Errorf("invalid local address family: %d", addressFamily)
	}

	_, err = buf.Read(localaddress)
	if err != nil {
		return nil, 0, nil, 0, err
	}

	_, err = buf.Read(portBuf[:])
	if err != nil {
		return nil, 0, nil, 0, err
	}
	localport := binary.BigEndian.Uint16(portBuf[:])

	//Parse remote address and port of the remote service to be proxied within the client machine
	//-------------------------------------------------------------------------------------------
	addressFamily, err = util.ReadVarInt(buf)
	if err != nil {
		return nil, 0, nil, 0, err
	}

	if addressFamily == util.SSHAFIpv4 {
		remoteaddress = make([]byte, 4)
	} else if addressFamily == util.SSHAFIpv6 {
		remoteaddress = make([]byte, 16)
	} else {
		return nil, 0, nil, 0, fmt.Errorf("invalid remote address family: %d", addressFamily)
	}

	_, err = buf.Read(remoteaddress)
	if err != nil {
		return nil, 0, nil, 0, err
	}

	_, err = buf.Read(portBuf[:])
	if err != nil {
		return nil, 0, nil, 0, err
	}
	remoteport := binary.BigEndian.Uint16(portBuf[:])

	return localaddress, localport, remoteaddress, remoteport, nil
}


// readFirstMsg returns (msgType, payload, err) from an ssh3.Channel.
func readFirstMsg(ctx context.Context, ch ssh3.Channel) (byte, []byte, error) {
    // Try a NextMessage-style API
    if r, ok := any(ch).(interface {
        NextMessage(context.Context) (byte, []byte, error)
    }); ok {
        return r.NextMessage(ctx)
    }
    // Or a ReadMessage-style API
    if r, ok := any(ch).(interface {
        ReadMessage(context.Context) (byte, []byte, error)
    }); ok {
        return r.ReadMessage(ctx)
    }
    return 0, nil, fmt.Errorf("channel doesn't expose a message-read method")
}


func (c *Client) RunSession(tty *os.File, forwardSSHAgent bool, command ...string) error {

	ctx := c.Context()

	//Managing incomming channels globally
	//TODO: for reverseTCP is required migrating here the management.
	go func() {
		for {
			channel, err := c.AcceptChannel(c.Context())
			if err != nil {
				log.Debug().Msgf("Error accepting channel")
				// ctx canceled, conn closed, or fatal; exit loop
				return
			}

			typ := channel.ChannelType()
			log.Debug().Msgf("New channel type %s \n", typ)

			if  strings.HasPrefix(typ, "open-request-reverse-udp") {
				//return nil, nil, fmt.Errorf("not a reverse-udp channel: %q", typ)
				localUDPAddr, remoteUDPAddr, err := parseAddrsFromChannelType(typ)
				log.Debug().Msgf("start reverse TCP forwarding from %s to %s \n", localUDPAddr, remoteUDPAddr)
				conn, err := net.DialUDP("udp", nil, remoteUDPAddr)
				if err != nil {
					return
				}
				forwardReverseUDPInBackground(ctx, channel, conn)
				if err != nil {
					channel.Close()
					return
				}
			}

			switch channel.ChannelType() {
			default:
				// Unknown/unwanted channel -> close or log
				channel.Close()
			}
		}
	}()


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
		go func() {
			for {
				forwardChannel, err := c.AcceptChannel(ctx)
				if err != nil {
					if err != context.Canceled {
						log.Error().Msgf("could not accept forwarding channel: %s", err.Error())
					}
					return
				} else if forwardChannel.ChannelType() != "agent-connection" {
					log.Error().Msgf("unexpected server-initiated channel: %s", channel.ChannelType())
					return
				}
				log.Debug().Msg("new agent connection, forwarding")
				go func() {
					err = forwardAgent(ctx, forwardChannel)
					if err != nil {
						log.Error().Msgf("agent forwarding error: %s", err.Error())
						c.Close()
					}
				}()
			}
		}()
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
