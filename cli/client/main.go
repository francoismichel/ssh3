package main

import (
	// "bufio"
	// "bytes"
	// "context"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	osuser "os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"ssh3"
	"ssh3/auth"
	"ssh3/cli/client/winsize"
	ssh3Messages "ssh3/message"
	"ssh3/util"

	"github.com/kevinburke/ssh_config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func homedir() string {
	user, err := osuser.Current()
	if err == nil {
		return user.HomeDir
	} else {
		return os.Getenv("HOME")
	}
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

func mainWithStatusCode() int {
	// verbose := flag.Bool("v", false, "verbose")
	// quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose")
	privKeyFile := flag.String("privkey", "", "private key file")
	pubkeyForAgent := flag.String("pubkey-for-agent", "", "if set, use an agent key whose public key matches the one in the specified path")
	passwordAuthentication := flag.Bool("use-password", false, "if set, do classical password authentication")
	insecure := flag.Bool("insecure", false, "if set, skip server certificate verification")
	issuerUrl := flag.String("use-oidc", "", "if set, force the use of OpenID Connect with the specified issuer url as parameter (it opens a browser window)")
	oidcConfigFileName := flag.String("oidc-config", "", "OpenID Connect json config file containing the \"client_id\" and \"client_secret\" fields needed for most identity providers")
	verbose := flag.Bool("v", false, "if set, enable verbose mode")
	doPKCE := flag.Bool("do-pkce", false, "if set perform PKCE challenge-response with oidc")
	forwardSSHAgent := flag.Bool("forward-agent", false, "if set, forwards ssh agent to be used with sshv2 connections on the remote host")
	forwardUDP := flag.String("forward-udp", "", "if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	forwardTCP := flag.String("forward-tcp", "", "if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	// enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	args := flag.Args()

	useOIDC := *issuerUrl != ""

	ssh3Dir := path.Join(homedir(), ".ssh3")
	os.MkdirAll(ssh3Dir, 0700)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if *verbose {
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}

	log.
		Debug().
		Str("KeylogFile", *keyLogFile).
		Str("PrivateKeyFile", *privKeyFile).
		Str("AgentPublicKey", *pubkeyForAgent).
		Bool("PasswordAuth", *passwordAuthentication).
		Bool("InsecureConn", *insecure).
		Str("OIDCIssuerURL", *issuerUrl).
		Str("OIDCConfigFile", *oidcConfigFileName).
		Bool("Verbose", *verbose).
		Bool("OIDCWithPKCE", *doPKCE).
		Bool("SSHAgentForwarding", *forwardSSHAgent).
		Str("UdPForwarding", *forwardUDP).
		Str("TCPForwarding", *forwardTCP).
		Msg("parsed CLI flags")

	log.Debug().Msg("parsing user known hosts")

	knownHostsPath := path.Join(ssh3Dir, "known_hosts")
	knownHosts, skippedLines, err := ssh3.ParseKnownHosts(knownHostsPath)
	log.
		Debug().
		Int("InvalidLines", len(skippedLines)).
		Int("Certificates", len(knownHosts)).
		Err(err).
		Msg("parsed known hosts")
	if len(skippedLines) != 0 {
		stringSkippedLines := []string{}
		for _, lineNumber := range skippedLines {
			log.
				Warn().
				Int("LineNumber", lineNumber).
				Msg("invalid line")
			stringSkippedLines = append(stringSkippedLines, fmt.Sprintf("%d", lineNumber))
		}
		log.Warn().Msgf("the following lines in %s are invalid: %s", knownHostsPath, strings.Join(stringSkippedLines, ", "))
	}
	if err != nil {
		log.Error().Msgf("there was an error when parsing known hosts: %s", err)
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	log.Debug().Err(err).Msg("opened tty")
	if err != nil {
		tty = nil
		log.Debug().Msg("error while opening tty: falling back and set to nil")
	}

	urlFromParam := args[0]
	log.Debug().Str("ConnectionURL", urlFromParam).Msg("got url")
	if !strings.HasPrefix(urlFromParam, "https://") {
		log.Debug().Str("ConnectionURL", urlFromParam).Msg("url has no prefix, adding")
		urlFromParam = fmt.Sprintf("https://%s", urlFromParam)
	}
	command := args[1:]
	log.Debug().Str("Command", strings.Join(command, " ")).Msg("got command")

	var localUDPAddr *net.UDPAddr = nil
	var remoteUDPAddr *net.UDPAddr = nil
	var localTCPAddr *net.TCPAddr = nil
	var remoteTCPAddr *net.TCPAddr = nil
	if *forwardUDP != "" {
		log.Debug().Str("UDPForwarding", *forwardUDP).Msg("setting up UDP forwarding")

		localPort, remoteIP, remotePort, err := parseAddrPort(*forwardUDP)
		log.
			Debug().
			Str("UDPForwarding", *forwardUDP).
			Int("LocalPort", localPort).
			IPAddr("RemoteIP", remoteIP).
			Int("RemotePort", remotePort).
			Err(err).
			Msg("parsed UDP forwarding address")
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
			log.
				Debug().
				Any("RemoteUDPAddress", remoteUDPAddr).
				Any("LocalUDPAddress", localUDPAddr).
				Msg("remote UDP address is an IPv4 address")
		} else if remoteIP.To16() != nil {
			localUDPAddr = &net.UDPAddr{
				IP:   net.IPv6loopback,
				Port: localPort,
			}
			log.
				Debug().
				Any("RemoteUDPAddress", remoteUDPAddr).
				Any("LocalUDPAddress", localUDPAddr).
				Msg("remote UDP address is an IPv6 address")
		} else {
			log.
				Error().
				Err(err).
				Any("RemoteUDPAddress", remoteUDPAddr).
				IPAddr("RemoteIP", remoteIP).
				Int("RemotePort", remotePort).
				Msgf("Unrecognized IP length %d", len(remoteIP))
			return -1
		}

		log.Trace().Msg("done setting up UDP forwarding")
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
			return -1
		}
	}

	var sshConfig *ssh_config.Config
	var configBytes []byte
	configPath := path.Join(homedir(), ".ssh", "config")
	configBytes, err = os.ReadFile(configPath)
	log.
		Debug().
		Str("SSHConfigFilePath", configPath).
		Int("ConfigBytes", len(configBytes)).
		Err(err).
		Msg("parsed ssh config")
	if err == nil {
		sshConfig, err = ssh_config.DecodeBytes(configBytes)
		if err != nil {
			log.Warn().Msgf("could not parse %s: %s, ignoring config", configPath, err)
			sshConfig = nil
		}
	} else if !os.IsNotExist(err) {
		log.Warn().Msgf("could not open %s: %s, ignoring config", configPath, err)
		sshConfig = nil
	}

	// default to oidc if no password or privkey
	var oidcConfig auth.OIDCIssuerConfig = nil
	var oidcConfigFile *os.File = nil
	if *oidcConfigFileName == "" {
		defaultFileName := path.Join(ssh3Dir, "oidc_config.json")
		oidcConfigFile, err = os.Open(defaultFileName)
		if err != nil && !os.IsNotExist(err) {
			log.Warn().Msgf("could not open %s: %s", defaultFileName, err.Error())
		}
	} else {
		oidcConfigFile, err = os.Open(*oidcConfigFileName)
		if err != nil {
			log.Error().Msgf("could not open %s: %s", *oidcConfigFileName, err.Error())
			return -1
		}
	}

	if oidcConfigFile != nil {
		data, err := io.ReadAll(oidcConfigFile)
		if err != nil {
			log.Error().Msgf("could not read oidc config file: %s", err.Error())
			return -1
		}
		if err = json.Unmarshal(data, &oidcConfig); err != nil {
			log.Error().Msgf("could not parse oidc config file: %s", err.Error())
			return -1
		}
	}

	// Duplicate logger set
	// log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		defer f.Close()
		keyLog = f
	}

	parsedUrl, err := url.Parse(urlFromParam)
	log.Debug().Any("ParsedURL", parsedUrl).Msg("parsed URL")
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	urlHostname, urlPort := parsedUrl.Hostname(), parsedUrl.Port()
	if urlPort == "" {
		urlPort = "443"
	}
	log.Debug().Str("Host", urlHostname).Str("Port", urlPort).Msg("parsed url and port")

	configHostname, configPort, configUser, configAuthMethods, err := ssh3.GetConfigForHost(urlHostname, sshConfig)
	log.
		Debug().
		Str("Host", urlHostname).
		Str("Port", urlPort).
		Str("ConfigHost", configHostname).
		Int("ConfigPort", configPort).
		Str("ConfigUser", configUser).
		Msg("fetched Host config")
	if err != nil {
		log.Error().Msgf("could not get config for %s: %s", urlHostname, err)
		return -1
	}

	hostname := configHostname
	if hostname == "" {
		hostname = urlHostname
	}
	log.
		Debug().
		Str("DialHostname", hostname).
		Str("URLHostname", urlHostname).
		Str("ConfigHostname", configHostname).
		Msg("set hostname")

	hostnameIsAnIP := net.ParseIP(hostname) != nil

	port := configPort
	if port == -1 && urlPort != "" {
		port, err = strconv.Atoi(urlPort)
		if err != nil {
			log.Error().Msgf("invalid port number: %s: %s", urlPort, err)
			return -1
		}
	}
	log.Debug().Int("Port", port).Int("ConfigPort", configPort).Str("URLPort", urlPort).Msg("set port")

	username := parsedUrl.User.Username()
	if username == "" {
		username = parsedUrl.Query().Get("user")
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
		log.Error().Msgf("no username could be found")
		return -1
	}

	urlQuery := parsedUrl.Query()
	urlQuery.Set("user", username)
	parsedUrl.RawQuery = urlQuery.Encode()
	requestUrl := parsedUrl.String()

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	tlsConf := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: *insecure,
		KeyLogWriter:       keyLog,
		NextProtos:         []string{http3.NextProtoH3},
	}

	if certs, ok := knownHosts[hostname]; ok {
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
			return -1
		}
		agentClient = agent.NewClient(conn)
		keys, err := agentClient.List()
		if err != nil {
			log.Error().Msgf("Failed to list agent keys: %s", err)
			return -1
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

	qClient, err := quic.DialAddrEarly(ctx,
		fmt.Sprintf("%s:%d", hostname, port),
		tlsConf,
		&qconf)
	if err != nil {
		if transportErr, ok := err.(*quic.TransportError); ok {
			if transportErr.ErrorCode.IsCryptoError() {
				if tty == nil {
					log.Error().Msgf("insecure server cert in non-terminal session, aborting")
					return -1
				}
				if _, ok = knownHosts[hostname]; ok {
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
		if *privKeyFile != "" {
			authMethods = append(authMethods, ssh3.NewPrivkeyFileAuthMethod(*privKeyFile))
		}

		if *pubkeyForAgent != "" {
			if agentClient == nil {
				log.Warn().Msgf("specified a public key (%s) but no agent is running", *pubkeyForAgent)
			} else {
				var pubkey ssh.PublicKey = nil
				if *pubkeyForAgent != "" {
					pubKeyBytes, err := os.ReadFile(*pubkeyForAgent)
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

		if *passwordAuthentication {
			authMethods = append(authMethods, ssh3.NewPasswordAuthMethod())
		}

	} else {
		// for now, only perform OIDC if it was explicitly asked by the user
		if *issuerUrl != "" {
			for _, issuerConfig := range oidcConfig {
				if *issuerUrl == issuerConfig.IssuerUrl {
					authMethods = append(authMethods, ssh3.NewOidcAuthMethod(*doPKCE, issuerConfig))
				}
			}
		} else {
			log.Error().Msgf("OIDC was asked explicitly bit did not find suitable issuer URL")
			return -1
		}
	}

	authMethods = append(authMethods, configAuthMethods...)

	if *issuerUrl == "" {
		for _, issuerConfig := range oidcConfig {
			authMethods = append(authMethods, ssh3.NewOidcAuthMethod(*doPKCE, issuerConfig))
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
			log.Debug().Msg("attempting pk auth")

			identity, err = m.IntoIdentityWithoutPassphrase()
			log.Debug().Err(err).Msg("attempted loading key without password")
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
			token, err := auth.Connect(context.Background(), m.OIDCConfig(), m.OIDCConfig().IssuerUrl, *doPKCE)
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

func main() {
	os.Exit(mainWithStatusCode())
}
