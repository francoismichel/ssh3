package main

import (
	// "bufio"
	// "bytes"
	// "context"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	testdata "ssh3"
	ssh3 "ssh3/src"
	"ssh3/src/auth"
	ssh3Messages "ssh3/src/message"
	"ssh3/src/util"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type windowSize struct {
	NRows       uint16
	NCols       uint16
	PixelWidth  uint16
	PixelHeight uint16
}

func getWinsize() (windowSize, error) {
	var winSize windowSize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdin), uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(&winSize)))
	var err error = nil
	if errno != 0 {
		err = errno
	}
	return winSize, err
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

func parseAddrPort(addrPort string) (localPort int, remoteIP net.IP, remotePort int, err error) {
	array := strings.Split(addrPort, "/")
	localPort, err = strconv.Atoi(array[0])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("could not convert %s to int: %s", array[0], err)
	} else if localPort > 0xFFFF {
		return 0, nil, 0, fmt.Errorf("UDP port too large %d", localPort)
	}
	array = strings.Split(array[1], "@")
	remoteIP = net.ParseIP(array[0])
	if remoteIP == nil {
		return 0, nil, 0, fmt.Errorf("could not parse IP %s", array[0])
	}
	remotePort, err = strconv.Atoi(array[1])
	if err != nil {
		return 0, nil, 0, fmt.Errorf("could not convert %s to int: %s", array[1], err)
	} else if localPort > 0xFFFF {
		return 0, nil, 0, fmt.Errorf("UDP port too large %d", remotePort)
	}
	return localPort, remoteIP, remotePort, err
}

func main() {
	// verbose := flag.Bool("v", false, "verbose")
	// quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	privKeyFile := flag.String("privkey", "", "private key file")
	useAgent := flag.Bool("use-agent", false, "if set, uses the running SSH agent to perform pubkey")
	pubkeyForAgent := flag.String("pubkey-for-agent", "", "(implies -use-agent) if set, use an agent key whose public key matches the one in the specified path")
	passwordAuthentication := flag.Bool("use-password", false, "do classical password authentication")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	addRootCA := flag.String("add-root-ca", "", "add root CA from specified path")
	issuerUrl := flag.String("issuer-url", "https://accounts.google.com", "openid issuer url")
	oidcConfigFileName := flag.String("oidc-config", "", "oidc json config file containing the \"client_id\" and \"client_secret\" fields")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	doPKCE := flag.Bool("do-pkce", false, "if set perform PKCE challenge-response with oidc (currently not working)")
	forwardSSHAgent := flag.Bool("forward-agent", false, "if set, forwards ssh agent to be used with sshv2 connections on the remote host")
	forwardUDP := flag.String("forward-udp", "", "if set, takes a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	forwardTCP := flag.String("forward-tcp", "", "if set, takes a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	// enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	args := flag.Args()

	host := args[0]
	command := args[1:]

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if *verbose {
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}

	var localUDPAddr *net.UDPAddr = nil
	var remoteUDPAddr *net.UDPAddr = nil
	var localTCPAddr *net.TCPAddr = nil
	var remoteTCPAddr *net.TCPAddr = nil
	if *forwardUDP != "" {
		localPort, remoteIP, remotePort, err := parseAddrPort(*forwardUDP)
		if err != nil {
			log.Error().Msgf("UDP forwarding parsing error %s", err)
		}
		remoteUDPAddr = &net.UDPAddr{
			IP:   remoteIP,
			Port: remotePort,
		}
		if remoteIP.To4() != nil {
			localUDPAddr = &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: localPort,
			}
		} else if remoteIP.To16() != nil {
			localUDPAddr = &net.UDPAddr{
				IP:   net.IPv6loopback,
				Port: localPort,
			}
		} else {
			log.Error().Msgf("Unrecognized IP length %d", len(remoteIP))
			return
		}
	}
	if *forwardTCP != "" {
		localPort, remoteIP, remotePort, err := parseAddrPort(*forwardTCP)
		if err != nil {
			log.Error().Msgf("UDP forwarding parsing error %s", err)
		}
		remoteTCPAddr = &net.TCPAddr{
			IP:   remoteIP,
			Port: remotePort,
		}
		if remoteIP.To4() != nil {
			localTCPAddr = &net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: localPort,
			}
		} else if remoteIP.To16() != nil {
			localTCPAddr = &net.TCPAddr{
				IP:   net.IPv6loopback,
				Port: localPort,
			}
		} else {
			log.Error().Msgf("Unrecognized IP length %d", len(remoteIP))
			return
		}
	}

	// default to oidc if no password or privkey
	var err error = nil
	var oidcConfig *auth.OIDCConfig = nil
	var oidcConfigFile *os.File = nil
	if *privKeyFile == "" && *useAgent == false && !*passwordAuthentication && *oidcConfigFileName == "" {
		defaultFileName := "/etc/ssh3/oidc_config.json"
		oidcConfigFile, err = os.Open(defaultFileName)
		if err != nil {
			log.Warn().Msgf("could not open %s: %s", defaultFileName, err.Error())
		}
	} else if *oidcConfigFileName != "" {
		oidcConfigFile, err = os.Open(*oidcConfigFileName)
		if err != nil {
			log.Warn().Msgf("could not open %s: %s", *oidcConfigFileName, err.Error())
			return
		}
	}

	if oidcConfigFile != nil {
		oidcConfig = new(auth.OIDCConfig)
		data, err := io.ReadAll(oidcConfigFile)
		if err != nil {
			log.Error().Msgf("could not read oidc config file: %s", err.Error())
			return
		}
		if err = json.Unmarshal(data, oidcConfig); err != nil {
			log.Error().Msgf("could not parse oidc config file: %s", err.Error())
			return
		}
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	if *addRootCA != "" {
		testdata.AddRootCA(pool, *addRootCA)
	}

	var qconf quic.Config

	qconf.MaxIncomingStreams = 10
	qconf.Allow0RTT = true
	qconf.EnableDatagrams = true

	tlsConf := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: *insecure,
		KeyLogWriter:       keyLog,
		NextProtos:         []string{http3.NextProtoH3},
	}

	qconf.KeepAlivePeriod = 1 * time.Second
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      &qconf,
		EnableDatagrams: true,
	}

	ctx, _ := context.WithCancelCause(context.Background())

	defer roundTripper.Close()

	log.Printf("GET %s", host)
	parsedUrl, err := url.Parse(host)
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	hostname, port := parsedUrl.Hostname(), parsedUrl.Port()
	if port == "" {
		port = "443"
	}
	log.Debug().Msgf("dialing host at %s", fmt.Sprintf("%s:%s", hostname, port))

	qClient, err := quic.DialAddrEarly(ctx,
		fmt.Sprintf("%s:%s", hostname, port),
		tlsConf,
		&qconf)
	if err != nil {
		log.Error().Msgf("could not create client QUIC connection: %s", err)
		return
	}

	// dirty hack: ensure only one QUIC connection is used
	roundTripper.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
		return qClient, nil
	}

	// Do 0RTT GET requests here if needed
	// Currently, we don't need it but we could use it to retrieve
	// convig or version info from the server
	qClient.HandshakeComplete()
	log.Debug().Msgf("QUIC handshake complete")
	// Now, we're 1-RTT, we can get the TLS exporter and create the conversation
	tls := qClient.ConnectionState().TLS
	conv, err := ssh3.NewClientConversation(30000, 10, &tls)
	if err != nil {
		log.Error().Msgf("could not create new client conversation: %s", err)
		return
	}

	// the connection struct is created, not build the request used to establish the connection

	req, err := http.NewRequest("CONNECT", host, nil)
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}
	req.Proto = "ssh3"

	username := parsedUrl.User.Username()
	if username == "" {
		username = parsedUrl.Query().Get("user")
	}

	var identityMethods []interface{}
	if *privKeyFile != "" {
		identityMethods = append(identityMethods, ssh3.NewPrivkeyFileAuthMethod(*privKeyFile))
	}

	var agentClient agent.ExtendedAgent
	var agentKeys []ssh.PublicKey

	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			log.Error().Msgf("Failed to open SSH_AUTH_SOCK: %s", err)
			return
		}
		agentClient = agent.NewClient(conn)
		keys, err := agentClient.List()
		if err != nil {
			log.Error().Msgf("Failed to list agent keys: %s", err)
			return
		}
		for _, key := range keys {
			agentKeys = append(agentKeys, key)
		}
	}

	if *useAgent || *pubkeyForAgent != "" {
		var pubkey ssh.PublicKey = nil
		if *pubkeyForAgent != "" {
			pubKeyBytes, err := os.ReadFile(*pubkeyForAgent)
			if err != nil {
				log.Error().Msgf("could not load public key file: %s", err)
				return
			}
			pubkey, _, _, _, err = ssh.ParseAuthorizedKey(pubKeyBytes)
			if err != nil {
				log.Error().Msgf("could not parse public key: %s", err)
				return
			}
		}

		for _, candidateKey := range agentKeys {
			if pubkey == nil || bytes.Equal(candidateKey.Marshal(), pubkey.Marshal()) {
				log.Debug().Msgf("found key in agent: %s", candidateKey)
				identityMethods = append(identityMethods, ssh3.NewAgentAuthMethod(candidateKey))
			}
		}
	}
	if *passwordAuthentication {
		identityMethods = append(identityMethods, ssh3.NewPasswordAuthMethod())
	}

	if oidcConfig != nil {
		identityMethods = append(identityMethods, ssh3.NewOidcAuthMethod(*issuerUrl, *doPKCE, oidcConfig))
	}

	var identity ssh3.Identity
	for _, method := range identityMethods {
		switch m := method.(type) {
		case *ssh3.PasswordAuthMethod:
			fmt.Printf("password for %s:", parsedUrl.String())
			password, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				log.Error().Msgf("could not get password: %s", err)
				return
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
						return
					}
					passphrase := string(passphraseBytes)
					identity, err = m.IntoIdentityPassphrase(passphrase)
					if err != nil {
						log.Error().Msgf("could not load private key: %s", err)
						return
					}
				}
			}
		case *ssh3.OidcAuthMethod:
			token, err := auth.Connect(context.Background(), oidcConfig, *issuerUrl, *doPKCE)
			if err != nil {
				log.Error().Msgf("could not get token: %s", err)
				return
			}
			identity = m.IntoIdentity(token)
		}
		// currently only tries a single identity (the first one), but the goal is to
		// try all identities, similarly to OpenSSH
		break
	}

	if identity == nil {
		log.Error().Msg("no suitable identity found")
		return
	}

	err = identity.SetAuthorizationHeader(req, username, conv)
	if err != nil {
		log.Error().Msgf("could not set authorization header in HTTP request: %s", err)
	}

	log.Debug().Msgf("send CONNECT request to the server")
	err = conv.EstablishClientConversation(req, roundTripper)
	if err != nil {
		log.Error().Msgf("Could not open channel: %+v", err)
		os.Exit(-1)
	}

	ctx = conv.Context()

	channel, err := conv.OpenChannel("session", 30000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open channel: %+v", err)
		os.Exit(-1)
	}

	log.Debug().Msgf("opened new session channel")

	if *forwardSSHAgent {
		_, err := channel.WriteData([]byte("forward-agent"), ssh3Messages.SSH_EXTENDED_DATA_NONE)
		if err != nil {
			log.Error().Msgf("could not forward agent: %s", err.Error())
			return
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
			windowSize, err := getWinsize()
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
				return
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
		return
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
			return
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
			return
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
				fmt.Fprintf(os.Stderr, "pty request not implemented\n")
			case *ssh3Messages.X11Request:
				fmt.Fprintf(os.Stderr, "x11 request not implemented\n")
			case *ssh3Messages.ShellRequest:
				fmt.Fprintf(os.Stderr, "shell request not implemented\n")
			case *ssh3Messages.ExecRequest:
				fmt.Fprintf(os.Stderr, "exec request not implemented\n")
			case *ssh3Messages.SubsystemRequest:
				fmt.Fprintf(os.Stderr, "subsystem request not implemented\n")
			case *ssh3Messages.WindowChangeRequest:
				fmt.Fprintf(os.Stderr, "windowchange request not implemented\n")
			case *ssh3Messages.SignalRequest:
				fmt.Fprintf(os.Stderr, "signal request not implemented\n")
			case *ssh3Messages.ExitStatusRequest:
				log.Info().Msgf("ssh3: process exited with status: %d\n", requestMessage.ExitStatus)
				return
			case *ssh3Messages.ExitSignalRequest:
				log.Info().Msgf("ssh3: process exited with signal: %s: %s\n", requestMessage.SignalNameWithoutSig, requestMessage.ErrorMessageUTF8)
				return
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
