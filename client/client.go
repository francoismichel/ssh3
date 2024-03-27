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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth/oidc"
	"github.com/francoismichel/ssh3/client/winsize"
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

type Client struct {
	qconn quic.EarlyConnection
	*ssh3.Conversation
}

func Dial(ctx context.Context, options *Options, qconn quic.EarlyConnection,
	roundTripper *http3.RoundTripper,
	sshAgent agent.ExtendedAgent) (*Client, error) {

	hostUrl := url.URL{}
	hostUrl.Scheme = "https"
	hostUrl.Host = options.URLHostnamePort()
	hostUrl.Path = options.UrlPath()
	urlQuery := hostUrl.Query()
	urlQuery.Set("user", options.Username())
	hostUrl.RawQuery = urlQuery.Encode()
	requestUrl := hostUrl.String()

	var qconf quic.Config

	qconf.MaxIncomingStreams = 10
	qconf.Allow0RTT = true
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

	var identity ssh3.Identity
	for _, method := range options.authMethods {
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
	err = identity.SetAuthorizationHeader(req, options.Username(), conv)
	if err != nil {
		log.Error().Msgf("could not set authorization header in HTTP request: %s", err)
		return nil, err
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

func (c *Client) ForwardUDP(ctx context.Context, localUDPAddr *net.UDPAddr, remoteUDPAddr *net.UDPAddr) (*net.UDPAddr, error) {
	log.Debug().Msgf("start UDP forwarding from %s to %s", localUDPAddr, remoteUDPAddr)
	conn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		log.Error().Msgf("could not listen on UDP socket: %s", err)
		return nil, err
	}
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

func (c *Client) RunSession(tty *os.File, forwardSSHAgent bool, command ...string) error {

	ctx := c.Context()

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
