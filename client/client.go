package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	osuser "os/user"

	"github.com/kevinburke/ssh_config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/client/winsize"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

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
	options *Options
	ssh3Dir string
	tty *os.File
	oidcConfig auth.OIDCIssuerConfig
	sshConfig *ssh_config.Config
	TLSConfig *tls.Config
}


func NewClient(options *Options, tty *os.File, ssh3Dir string, oidcConfig auth.OIDCIssuerConfig, sshConfig *ssh_config.Config) *Client {
	return &Client{
		options: options,
		ssh3Dir: ssh3Dir,
		tty: tty,
		oidcConfig: oidcConfig,
	}
}
func NewClientWithTLSConfig(options *Options, tty *os.File, ssh3Dir string, oidcConfig auth.OIDCIssuerConfig, sshConfig *ssh_config.Config, tlsConfig *tls.Config) *Client {
	return &Client{
		options: options,
		ssh3Dir: ssh3Dir,
		tty: tty,
		oidcConfig: oidcConfig,
		TLSConfig: tlsConfig,
	}
}


func (c *Client) Dial(hostUrl string) (*ssh3.Conversation, error) {

	parsedUrl, err := url.Parse(hostUrl)
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	hostname, port := parsedUrl.Hostname(), parsedUrl.Port()
	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprint("%s:%d", hostname, port))
	if err != nil {
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	return c.DialPacketConn(udpConn, remoteAddr, parsedUrl)
}

func (c *Client) DialQUIC(conn quic.EarlyConnection, hostUrl *url.URL) (*ssh3.Conversation, error) {

	knownHostsPath := path.Join(c.ssh3Dir, "known_hosts")


	urlHostname, urlPort := hostUrl.Hostname(), hostUrl.Port()

	configHostname, configPort, configUser, configAuthMethods, err := ssh3.GetConfigForHost(urlHostname, c.sshConfig)
	if err != nil {
		log.Error().Msgf("could not get config for %s: %s", urlHostname, err)
		return nil, err
	}

	hostname := configHostname
	if hostname == "" {
		hostname = urlHostname
	}

	hostnameIsAnIP := net.ParseIP(hostname) != nil

	var port int
	if urlPort != "" {
		if parsedPort, err := strconv.Atoi(urlPort); err == nil && parsedPort < 0xffff {
			// There is a port in the CLI and the port is valid. Use the CLI port.
			port = parsedPort
		} else {
			// There is a port in the CLI but it is not valid.
			// use WithLevel(zerolog.FatalLevel) to log a fatal level, but let us handle
			// program termination. log.Fatal() exits with os.Exit(1).
			log.WithLevel(zerolog.FatalLevel).Str("Port", urlPort).Err(err).Msg("cli contains an invalid port")
			fmt.Fprintf(os.Stderr, "Bad port '%s'\n", urlPort)
			return nil, err
		}
	} else if configPort != -1 {
		// There is no port in the CLI, but one in a config file. Use the config port.
		port = configPort
	} else {
		// There is no port specified, neither in the CLI, nor in the configuration.
		port = 443
	}

	username := hostUrl.User.Username()
	if username == "" {
		username = hostUrl.Query().Get("user")
	}
	if username == "" {
		username = configUser
	}
	if username == "" {
		u, err := osuser.Current()
		if err == nil {
			username = u.Username
		} else {
			log.Error().Msgf("could not get current username: %s", err)
		}
	}
	if username == "" {
		return nil, fmt.Errorf("no username could be found")
	}

	urlQuery := hostUrl.Query()
	urlQuery.Set("user", username)
	hostUrl.RawQuery = urlQuery.Encode()
	requestUrl := hostUrl.String()

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	tlsConf := c.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: !c.options.verifyHostCertificate,
			NextProtos:         []string{http3.NextProtoH3},
		}
	}

	if certs, ok := c.options.knownHosts[hostname]; ok {
		foundSelfsignedSSH3 := false

		for _, cert := range certs {
			pool.AddCert(cert)
			if cert.VerifyHostname("selfsigned.ssh3") == nil {
				foundSelfsignedSSH3 = true
			}
		}

		// If no IP SAN was in the cert, then assume the self-signed cert at least matches the .ssh3 TLD
		if foundSelfsignedSSH3 {
			// Put "ssh3" as ServerName so that the TLS verification can succeed
			// Otherwise, TLS refuses to validate a certificate without IP SANs
			// if the hostname is an IP address.
			tlsConf.ServerName = "selfsigned.ssh3"
		}
	}

	var qconf quic.Config

	qconf.MaxIncomingStreams = 10
	qconf.Allow0RTT = true
	qconf.EnableDatagrams = true
	qconf.KeepAlivePeriod = 1 * time.Second

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      &qconf,
		EnableDatagrams: true,
	}

	ctx, _ := context.WithCancelCause(context.Background())

	defer roundTripper.Close()

	// connect to SSH agent if it exists
	var agentClient agent.ExtendedAgent
	var agentKeys []ssh.PublicKey

	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			log.Error().Msgf("Failed to open SSH_AUTH_SOCK: %s", err)
			return nil, err
		}
		agentClient = agent.NewClient(conn)
		keys, err := agentClient.List()
		if err != nil {
			log.Error().Msgf("Failed to list agent keys: %s", err)
			return nil, err
		}
		for _, key := range keys {
			agentKeys = append(agentKeys, key)
		}
	}

	log.Debug().Msgf("dialing QUIC host at %s", fmt.Sprintf("%s:%d", hostname, port))

	if hostnameIsAnIP {
		ip := net.ParseIP(hostname)
		if ip.To4() == nil && ip.To16() != nil {
			// enforce the square-bracketed notation for ipv6 UDP addresses
			hostname = fmt.Sprintf("[%s]", hostname)
		}
	}

	qClient, err := quic.DialEarly(ctx,
		remoteAddr,
		fmt.Sprintf("%s:%d", hostname, port),
		tlsConf,
		&qconf)
	if err != nil {
		if transportErr, ok := err.(*quic.TransportError); ok {
			if transportErr.ErrorCode.IsCryptoError() {
				log.Debug().Msgf("received QUIC crypto error on first connection attempt: %s", err)
				if tty == nil {
					log.Error().Msgf("insecure server cert in non-terminal session, aborting")
					return -1
				}
				if _, ok = c.options.knownHosts[hostname]; ok {
					log.Error().Msgf("The server certificate cannot be verified using the one installed in %s. "+
						"If you did not change the server certificate, it could be a machine-in-the-middle attack. "+
						"TLS error: %s", knownHostsPath, err)
					log.Error().Msgf("Aborting.")
					return -1
				}
				// bad certificates, let's mimic the OpenSSH's behaviour similar to host keys
				tlsConf.InsecureSkipVerify = true
				var peerCertificate *x509.Certificate
				certError := fmt.Errorf("we don't want to start a totally insecure connection")
				tlsConf.VerifyConnection = func(ctx tls.ConnectionState) error {
					peerCertificate = ctx.PeerCertificates[0]
					return certError
				}

				_, err := quic.DialAddrEarly(ctx,
					fmt.Sprintf("%s:%d", hostname, port),
					tlsConf,
					&qconf)
				if !errors.Is(err, certError) {
					log.Error().Msgf("could not create client QUIC connection: %s", err)
					return -1
				}
				// let's first check that the certificate is self-signed
				if err := peerCertificate.CheckSignatureFrom(peerCertificate); err != nil {
					log.Error().Msgf("the peer provided an unknown, insecure certificate, that is not self-signed: %s", err)
					return -1
				}
				// first, carriage return
				_, _ = tty.WriteString("\r")
				_, err = tty.WriteString("Received an unknown self-signed certificate from the server.\n\r" +
					"We recommend not using self-signed certificates.\n\r" +
					"This session is vulnerable a machine-in-the-middle attack.\n\r" +
					"Certificate fingerprint: " +
					"SHA256 " + util.Sha256Fingerprint(peerCertificate.Raw) + "\n\r" +
					"Do you want to add this certificate to ~/.ssh3/known_hosts (yes/no)? ")
				if err != nil {
					log.Error().Msgf("cound not write on /dev/tty: %s", err)
					return -1
				}

				answer := ""
				reader := bufio.NewReader(tty)
				for {
					answer, _ = reader.ReadString('\n')
					answer = strings.TrimSpace(answer)
					_, _ = tty.WriteString("\r") // always ensure a carriage return
					if answer == "yes" || answer == "no" {
						break
					}
					tty.WriteString("Invalid answer, answer \"yes\" or \"no\" ")
				}
				if answer == "no" {
					log.Info().Msg("Connection aborted")
					return 0
				}
				if err := ssh3.AppendKnownHost(knownHostsPath, hostname, peerCertificate); err != nil {
					log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
					return -1
				}
				tty.WriteString(fmt.Sprintf("Successfully added the certificate to %s, please rerun the command\n\r", knownHostsPath))
				return 0
			}
		}
		log.Error().Msgf("could not establish client QUIC connection: %s", err)
		return -1
	}

	// dirty hack: ensure only one QUIC connection is used
	roundTripper.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		return qClient, nil
	}

	// Do 0RTT GET requests here if needed
	// Currently, we don't need it but we could use it to retrieve
	// config or version info from the server
	// We could also allow user-defined safe/idempotent commands to run with 0-RTT
	qClient.HandshakeComplete()
	log.Debug().Msgf("QUIC handshake complete")
	// Now, we're 1-RTT, we can get the TLS exporter and create the conversation
	tls := qClient.ConnectionState().TLS
	conv, err := ssh3.NewClientConversation(30000, 10, &tls)
	if err != nil {
		log.Error().Msgf("could not create new client conversation: %s", err)
		return -1
	}

	// the connection struct is created, now build the request used to establish the connection
	req, err := http.NewRequest("CONNECT", requestUrl, nil)
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}
	req.Proto = "ssh3"
	req.Header.Set("User-Agent", ssh3.GetCurrentVersion())

	var authMethods []interface{}

	// Only do privkey and agent auth if OIDC is not asked explicitly
	if !useOIDC {
		if privkeyFile != "" {
			authMethods = append(authMethods, ssh3.NewPrivkeyFileAuthMethod(privkeyFile))
		}

		if pubkeyForAgent != "" {
			if agentClient == nil {
				log.Warn().Msgf("specified a public key (%s) but no agent is running", pubkeyForAgent)
			} else {
				var pubkey ssh.PublicKey = nil
				if pubkeyForAgent != "" {
					pubKeyBytes, err := os.ReadFile(pubkeyForAgent)
					if err != nil {
						log.Error().Msgf("could not load public key file: %s", err)
						return -1
					}
					pubkey, _, _, _, err = ssh.ParseAuthorizedKey(pubKeyBytes)
					if err != nil {
						log.Error().Msgf("could not parse public key: %s", err)
						return -1
					}
				}

				for _, candidateKey := range agentKeys {
					if pubkey == nil || bytes.Equal(candidateKey.Marshal(), pubkey.Marshal()) {
						log.Debug().Msgf("found key in agent: %s", candidateKey)
						authMethods = append(authMethods, ssh3.NewAgentAuthMethod(candidateKey))
					}
				}
			}
		}

		if passwordAuthentication {
			authMethods = append(authMethods, ssh3.NewPasswordAuthMethod())
		}

	} else {
		// for now, only perform OIDC if it was explicitly asked by the user
		if issuerUrl != "" {
			for _, issuerConfig := range oidcConfig {
				if issuerUrl == issuerConfig.IssuerUrl {
					authMethods = append(authMethods, ssh3.NewOidcAuthMethod(doPKCE, issuerConfig))
				}
			}
		} else {
			log.Error().Msgf("OIDC was asked explicitly bit did not find suitable issuer URL")
			return -1
		}
	}

	authMethods = append(authMethods, configAuthMethods...)

	if issuerUrl == "" {
		for _, issuerConfig := range oidcConfig {
			authMethods = append(authMethods, ssh3.NewOidcAuthMethod(doPKCE, issuerConfig))
		}
	}

	var identity ssh3.Identity
	for _, method := range authMethods {
		switch m := method.(type) {
		case *ssh3.PasswordAuthMethod:
			fmt.Printf("password for %s:", parsedUrl.String())
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				log.Error().Msgf("could not get password: %s", err)
				return -1
			}
			identity = m.IntoIdentity(string(password))
		case *ssh3.PrivkeyFileAuthMethod:
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
							identity = ssh3.NewAgentAuthMethod(pubkey).IntoIdentity(agentClient)
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
						return -1
					}
					passphrase := string(passphraseBytes)
					identity, err = m.IntoIdentityPassphrase(passphrase)
					if err != nil {
						log.Error().Msgf("could not load private key: %s", err)
						return -1
					}
				}
			} else if err != nil {
				log.Warn().Msgf("Could not load private key: %s", err)
			}
		case *ssh3.AgentAuthMethod:
			identity = m.IntoIdentity(agentClient)
		case *ssh3.OidcAuthMethod:
			token, err := auth.Connect(context.Background(), m.OIDCConfig(), m.OIDCConfig().IssuerUrl, doPKCE)
			if err != nil {
				log.Error().Msgf("could not get token: %s", err)
				return -1
			}
			identity = m.IntoIdentity(token)
		}
		// currently only tries a single identity (the first one), but the goal is to
		// try several identities, similarly to OpenSSH
		break
	}

	if identity == nil {
		log.Error().Msg("no suitable identity found")
		return -1
	}

	log.Debug().Msgf("try the following Identity: %s", identity)
	err = identity.SetAuthorizationHeader(req, username, conv)
	if err != nil {
		log.Error().Msgf("could not set authorization header in HTTP request: %s", err)
	}

	log.Debug().Msgf("send CONNECT request to the server")
	err = conv.EstablishClientConversation(req, roundTripper)
	if errors.Is(err, util.Unauthorized{}) {
		log.Error().Msgf("Access denied from the server: unauthorized")
		return -1
	} else if err != nil {
		log.Error().Msgf("Could not open channel: %+v", err)
		return -1
	}

}


func Run(hostUrl string, sshConfig *ssh_config.Config, insecure bool, ssh3Dir string, knownHosts map[string][]*x509.Certificate, keylogWriter io.Writer, tty *os.File,
	useOIDC bool, privkeyFile string, pubkeyForAgent string, passwordAuthentication bool, issuerUrl string, doPKCE bool,
	oidcConfig auth.OIDCIssuerConfig, forwardSSHAgent bool, command []string, localUDPAddr *net.UDPAddr, remoteUDPAddr *net.UDPAddr, localTCPAddr *net.TCPAddr, remoteTCPAddr *net.TCPAddr) int {

	ctx = conv.Context()

	channel, err := conv.OpenChannel("session", 30000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open channel: %+v", err)
		os.Exit(-1)
	}

	log.Debug().Msgf("opened new session channel")

	if forwardSSHAgent {
		_, err := channel.WriteData([]byte("forward-agent"), ssh3Messages.SSH_EXTENDED_DATA_NONE)
		if err != nil {
			log.Error().Msgf("could not forward agent: %s", err.Error())
			return -1
		}
		go func() {
			for {
				forwardChannel, err := conv.AcceptChannel(ctx)
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
						conv.Close()
					}
				}()
			}
		}()
	}

	if len(command) == 0 {
		// avoid requesting a pty on the other side if stdin is not a pty
		// similar behaviour to OpenSSH
		isATTY := term.IsTerminal(int(os.Stdin.Fd()))
		if isATTY {
			windowSize, err := winsize.GetWinsize()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not get window size: %+v", err)
				os.Exit(-1)
			}
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
				return -1
			}
			log.Debug().Msgf("sent pty request for session")
		}

		err = channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply:      true,
				ChannelRequest: &ssh3Messages.ShellRequest{},
			},
		)
		log.Debug().Msgf("sent shell request")
		// avoid making the terminal raw if stdin is not a TTY
		// similar behaviour to OpenSSH
		if isATTY {
			fd := os.Stdin.Fd()
			oldState, err := term.MakeRaw(int(fd))
			if err != nil {
				log.Fatal().Msgf("%s", err)
			}
			defer term.Restore(int(fd), oldState)
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
		return -1
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

	if localUDPAddr != nil && remoteUDPAddr != nil {
		log.Debug().Msgf("start forwarding from %s to %s", localUDPAddr, remoteUDPAddr)
		conn, err := net.ListenUDP("udp", localUDPAddr)
		if err != nil {
			log.Error().Msgf("could listen on UDP socket: %s", err)
			return -1
		}
		forwardings := make(map[string]ssh3.Channel)
		go func() {
			buf := make([]byte, 1500)
			for {
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					log.Error().Msgf("could read on UDP socket: %s", err)
					return
				}
				channel, ok := forwardings[addr.String()]
				if !ok {
					channel, err = conv.OpenUDPForwardingChannel(30000, 10, localUDPAddr, remoteUDPAddr)
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
	}

	if localTCPAddr != nil && remoteTCPAddr != nil {
		log.Debug().Msgf("start forwarding from %s to %s", localTCPAddr, remoteTCPAddr)
		conn, err := net.ListenTCP("tcp", localTCPAddr)
		if err != nil {
			log.Error().Msgf("could listen on TCP socket: %s", err)
			return -1
		}
		go func() {
			for {
				conn, err := conn.AcceptTCP()
				if err != nil {
					log.Error().Msgf("could read on UDP socket: %s", err)
					return
				}
				forwardingChannel, err := conv.OpenTCPForwardingChannel(30000, 10, localTCPAddr, remoteTCPAddr)
				if err != nil {
					log.Error().Msgf("could open new UDP forwarding channel: %s", err)
					return
				}
				forwardTCPInBackground(ctx, forwardingChannel, conn)
			}
		}()
	}

	defer conv.Close()
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
				return int(requestMessage.ExitStatus)
			case *ssh3Messages.ExitSignalRequest:
				log.Info().Msgf("ssh3: process exited with signal: %s: %s\n", requestMessage.SignalNameWithoutSig, requestMessage.ErrorMessageUTF8)
				return -1
			}
		case *ssh3Messages.DataOrExtendedDataMessage:
			switch message.DataType {
			case ssh3Messages.SSH_EXTENDED_DATA_NONE:
				_, err = os.Stdout.Write([]byte(message.Data))
				if err != nil {
					log.Fatal().Msgf("%s", err)
				}

				log.Debug().Msgf("received data %s", message.Data)
			case ssh3Messages.SSH_EXTENDED_DATA_STDERR:
				_, err = os.Stderr.Write([]byte(message.Data))
				if err != nil {
					log.Fatal().Msgf("%s", err)
				}

				log.Debug().Msgf("received stderr data %s", message.Data)
			}
		}
	}
}
