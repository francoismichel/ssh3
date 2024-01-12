package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	osuser "os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/client"
	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/kevinburke/ssh_config"
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

// Prepares the QUIC connection that will be used by SSH3
// If non-nil, use udpConn as transport (can be used for proxy jump)
// Otherwise, create a UDPConn from udp://host:port
func setupQUICConnection(ctx context.Context, skipHostVerification bool, keylog io.Writer, ssh3Dir string, certPool *x509.CertPool, knownHostsPath string, knownHosts ssh3.KnownHosts,
	oidcConfig []*auth.OIDCConfig, options *client.Options, proxyRemoteAddr *net.UDPAddr, tty *os.File) (quic.EarlyConnection, int) {

	var err error
	remoteAddr := proxyRemoteAddr
	if remoteAddr == nil {
		remoteAddr, err = net.ResolveUDPAddr("udp", options.URLHostnamePort())
		if err != nil {
			log.Error().Msgf("could not resolve UDP address: %s", err)
			return nil, -1
		}
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Error().Msgf("could not create UDP connection: %s", err)
		return nil, -1
	}

	tlsConf := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: skipHostVerification,
		NextProtos:         []string{http3.NextProtoH3},
		KeyLogWriter:       keylog,
		ServerName:         options.Hostname(),
	}

	var qconf quic.Config

	qconf.MaxIncomingStreams = 10
	qconf.Allow0RTT = true
	qconf.EnableDatagrams = true
	qconf.KeepAlivePeriod = 1 * time.Second

	if certs, ok := knownHosts[options.CanonicalHostFormat()]; ok {
		foundSelfsignedSSH3 := false

		for _, cert := range certs {
			certPool.AddCert(cert)
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

	log.Debug().Msgf("dialing QUIC host at %s", remoteAddr)
	qClient, err := quic.DialEarly(ctx,
		udpConn,
		remoteAddr,
		tlsConf,
		&qconf)
	if err != nil {
		if transportErr, ok := err.(*quic.TransportError); ok {
			if transportErr.ErrorCode.IsCryptoError() {
				log.Debug().Msgf("received QUIC crypto error on first connection attempt: %s", err)
				if tty == nil {
					log.Error().Msgf("insecure server cert in non-terminal session, aborting")
					return nil, -1
				}
				if _, ok := knownHosts[options.CanonicalHostFormat()]; ok {
					log.Error().Msgf("The server certificate cannot be verified using the one installed in %s. "+
						"If you did not change the server certificate, it could be a machine-in-the-middle attack. "+
						"TLS error: %s", knownHostsPath, err)
					log.Error().Msgf("Aborting.")
					return nil, -1
				}
				// bad certificates, let's mimic the OpenSSH's behaviour similar to host keys
				tlsConf.InsecureSkipVerify = true
				var peerCertificate *x509.Certificate
				certError := fmt.Errorf("we don't want to start a totally insecure connection")
				tlsConf.VerifyConnection = func(ctx tls.ConnectionState) error {
					peerCertificate = ctx.PeerCertificates[0]
					return certError
				}

				_, err := quic.DialEarly(ctx,
					udpConn,
					remoteAddr,
					tlsConf,
					&qconf)
				if !errors.Is(err, certError) {
					log.Error().Msgf("could not create client QUIC connection: %s", err)
					return nil, -1
				}
				// let's first check that the certificate is self-signed
				if err := peerCertificate.CheckSignatureFrom(peerCertificate); err != nil {
					log.Error().Msgf("the peer provided an unknown, insecure certificate, that is not self-signed: %s", err)
					return nil, -1
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
					return nil, -1
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
					return nil, 0
				}
				if err := ssh3.AppendKnownHost(knownHostsPath, options.CanonicalHostFormat(), peerCertificate); err != nil {
					log.Error().Msgf("could not append known host to %s: %s", knownHostsPath, err)
					return nil, -1
				}
				tty.WriteString(fmt.Sprintf("Successfully added the certificate to %s, please rerun the command\n\r", knownHostsPath))
				return nil, 0
			}
		}
		log.Error().Msgf("could not establish client QUIC connection: %s", err)
		return nil, -1
	}

	return qClient, 0
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
	} else if remotePort > 0xFFFF {
		return 0, nil, 0, fmt.Errorf("UDP port too large %d", remotePort)
	}
	return localPort, remoteIP, remotePort, err
}

func getConfigOptions(hostUrl *url.URL, sshConfig *ssh_config.Config) (*client.Options, error) {
	urlHostname, urlPort := hostUrl.Hostname(), hostUrl.Port()

	configHostname, configPort, configUser, configUrlPath, configAuthMethods, err := ssh3.GetConfigForHost(urlHostname, sshConfig)
	if err != nil {
		log.Error().Msgf("Could not get config for %s: %s", urlHostname, err)
		return nil, err
	}

	hostname := configHostname
	if hostname == "" {
		hostname = urlHostname
	}

	port := 443
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

	urlPath := hostUrl.Path
	if urlPath == "" {
		urlPath = configUrlPath
	}
	return client.NewOptions(username, hostname, port, urlPath, configAuthMethods)
}

func getConnectionMaterialFromURL(hostUrl *url.URL, sshConfig *ssh_config.Config, cliAuthMethods []interface{}) (agent.ExtendedAgent, *client.Options, error) {
	configOptions, err := getConfigOptions(hostUrl, sshConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("could not apply config to %s: %s", hostUrl, err)
	}

	var agentClient agent.ExtendedAgent
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath != "" {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return nil, nil, fmt.Errorf("cailed to open SSH_AUTH_SOCK: %s", err)
		}
		agentClient = agent.NewClient(conn)
	}

	var authMethods []interface{}
	authMethods = append(authMethods, cliAuthMethods...)
	authMethods = append(authMethods, configOptions.AuthMethods()...)

	options, err := client.NewOptions(configOptions.Username(), configOptions.Hostname(), configOptions.Port(), configOptions.UrlPath(), authMethods)
	if err != nil {
		return nil, nil, fmt.Errorf("could not instantiate invalid options: %s", err)
	}
	return agentClient, options, nil
}

func mainWithStatusCode() int {
	keyLogFile := flag.String("keylog", "", "Write QUIC TLS keys and master secret in the specified keylog file: only for debugging purpose")
	privKeyFile := flag.String("privkey", "", "private key file")
	pubkeyForAgent := flag.String("pubkey-for-agent", "", "if set, use an agent key whose public key matches the one in the specified path")
	passwordAuthentication := flag.Bool("use-password", false, "if set, do classical password authentication")
	insecure := flag.Bool("insecure", false, "if set, skip server certificate verification")
	issuerUrl := flag.String("use-oidc", "", "if set, force the use of OpenID Connect with the specified issuer url as parameter (it opens a browser window)")
	oidcConfigFileName := flag.String("oidc-config", "", "OpenID Connect json config file containing the \"client_id\" and \"client_secret\" fields needed for most identity providers")
	verbose := flag.Bool("v", false, "if set, enable verbose mode")
	displayVersion := flag.Bool("version", false, "if set, displays the software version on standard output and exit")
	doPKCE := flag.Bool("do-pkce", false, "if set perform PKCE challenge-response with oidc")
	forwardSSHAgent := flag.Bool("forward-agent", false, "if set, forwards ssh agent to be used with sshv2 connections on the remote host")
	forwardUDP := flag.String("forward-udp", "", "if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	forwardTCP := flag.String("forward-tcp", "", "if set, take a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	proxyJump := flag.String("proxy-jump", "", "if set, performs a proxy jump using the specified remote host as proxy (requires server with version >= 0.1.5)")
	flag.Parse()
	args := flag.Args()

	if *displayVersion {
		fmt.Fprintln(os.Stdout, filepath.Base(os.Args[0]), "version", ssh3.GetCurrentSoftwareVersion())
		return 0
	}

	useOIDC := *issuerUrl != ""

	ssh3Dir := path.Join(homedir(), ".ssh3")
	os.MkdirAll(ssh3Dir, 0700)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if *verbose && os.Getenv("SSH3_LOG_LEVEL") != "trace" {
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}

	if len(args) == 0 {
		log.Error().Msgf("no remote host specified, exit")
		flag.Usage()
		os.Exit(-1)
	}

	log.Debug().Msgf("version %s", ssh3.GetCurrentSoftwareVersion())

	knownHostsPath := path.Join(ssh3Dir, "known_hosts")
	knownHosts, skippedLines, err := ssh3.ParseKnownHosts(knownHostsPath)
	if len(skippedLines) != 0 {
		stringSkippedLines := []string{}
		for _, lineNumber := range skippedLines {
			stringSkippedLines = append(stringSkippedLines, fmt.Sprintf("%d", lineNumber))
		}
		log.Warn().Msgf("the following lines in %s are invalid: %s", knownHostsPath, strings.Join(stringSkippedLines, ", "))
	}
	if err != nil {
		log.Error().Msgf("there was an error when parsing known hosts: %s", err)
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = nil
	}

	urlFromParam := args[0]
	if !strings.HasPrefix(urlFromParam, "https://") {
		urlFromParam = fmt.Sprintf("https://%s", urlFromParam)
	}
	command := args[1:]

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
			return -1
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
			return -1
		}
	}

	var sshConfig *ssh_config.Config
	var configBytes []byte
	configPath := path.Join(homedir(), ".ssh", "config")
	configBytes, err = os.ReadFile(configPath)
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
		log.Debug().Msgf("no OIDC config file specified, use default file: %s", defaultFileName)
		oidcConfigFile, err = os.Open(defaultFileName)
		if os.IsNotExist(err) {
			log.Debug().Msgf("%s does not exist", defaultFileName)
		} else if err != nil {
			log.Warn().Msgf("could not open %s: %s", defaultFileName, err.Error())
		}
	} else {
		log.Debug().Msgf("open OIDC config from %s", *oidcConfigFileName)
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
		log.Debug().Msgf("successfully parsed OIDC config")
	}

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		defer f.Close()
		keyLog = f
	}

	var cliAuthMethods []interface{}
	// Only do privkey and agent auth if OIDC is not asked explicitly
	if !useOIDC {
		if *privKeyFile != "" {
			cliAuthMethods = append(cliAuthMethods, ssh3.NewPrivkeyFileAuthMethod(*privKeyFile))
		}

		if *pubkeyForAgent != "" {
			if os.Getenv("SSH_AUTH_SOCK") == "" {
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
					cliAuthMethods = append(cliAuthMethods, ssh3.NewAgentAuthMethod(pubkey))
				}
			}
		}

		if *passwordAuthentication {
			cliAuthMethods = append(cliAuthMethods, ssh3.NewPasswordAuthMethod())
		}

	} else {
		// for now, only perform OIDC if it was explicitly asked by the user
		if *issuerUrl != "" {
			log.Debug().Msgf("add OIDC auth, %d issuers in configs", len(oidcConfig))
			for _, issuerConfig := range oidcConfig {
				if *issuerUrl == issuerConfig.IssuerUrl {
					log.Debug().Msgf("found issuer %s matching the issuer specified in the command-line", issuerConfig.IssuerUrl)
					cliAuthMethods = append(cliAuthMethods, ssh3.NewOidcAuthMethod(*doPKCE, issuerConfig))
				} else {
					log.Debug().Msgf("issuer %s does not match issuer URL %s specified in the command-line", issuerConfig.IssuerUrl, *issuerUrl)
				}
			}
		} else {
			log.Error().Msgf("OIDC was asked explicitly but did not find suitable issuer URL")
			return -1
		}
	}

	parsedUrl, err := url.Parse(urlFromParam)
	if err != nil {
		log.Error().Msgf("could not parse URL: %s", err)
		return -1
	}

	ctx := context.Background()

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal().Msgf("%s", err)
	}

	agentClient, options, err := getConnectionMaterialFromURL(parsedUrl, sshConfig, cliAuthMethods)
	if err != nil {
		log.Error().Msgf("Could not get connection material for %s: %s", parsedUrl, err)
		return -1
	}

	if *proxyJump == "" && sshConfig != nil {
		*proxyJump, err = sshConfig.Get(parsedUrl.Hostname(), "UDPProxyJump")
		if err != nil {
			log.Error().Msgf("Could not get UDPProxyJump config value: %s", err)
			return -1
		}
	}

	var proxyAddress *net.UDPAddr
	if *proxyJump != "" {
		if !strings.HasPrefix(*proxyJump, "https://") {
			*proxyJump = fmt.Sprintf("https://%s", *proxyJump)
		}
		proxyParsedUrl, err := url.Parse(*proxyJump)
		if err != nil {
			log.Error().Msgf("Could not parse proxy host URL %s: %s", *proxyJump, err)
			return -1
		}
		proxyAgentClient, proxyOptions, err := getConnectionMaterialFromURL(proxyParsedUrl, sshConfig, cliAuthMethods)
		if err != nil {
			log.Error().Msgf("Could not get connection material for proxy %s: %s", proxyParsedUrl, err)
			return -1
		}
		qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, oidcConfig, proxyOptions, nil, tty)

		if qconn == nil {
			if status != 0 {
				log.Error().Msgf("could not setup transport for proxy client: %s", err)
			}
			return status
		}

		roundTripper := &http3.RoundTripper{
			EnableDatagrams: true,
		}

		proxyClient, err := client.Dial(ctx, proxyOptions, qconn, roundTripper, proxyAgentClient)
		if err != nil {
			log.Error().Msgf("could not establish SSH3 proxy conversation: %s", err)
			return -1
		}

		baseAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			log.Error().Msgf("Could not resolve 127.0.0.1:0: %s", err)
			return -1
		}
		remoteAddr, err := net.ResolveUDPAddr("udp", options.URLHostnamePort())
		if err != nil {
			log.Error().Msgf("Could not resolve remote address %s: %s", options.URLHostnamePort(), err)
			return -1
		}
		addr, err := proxyClient.ForwardUDP(ctx, baseAddr, remoteAddr)
		if err != nil {
			log.Error().Msgf("Could not forward UDP for proxy jump: %s", err)
			return -1
		}
		proxyAddress = addr
		log.Debug().Msgf("started proxy jump at %s", proxyAddress)
	}

	qconn, status := setupQUICConnection(ctx, *insecure, keyLog, ssh3Dir, pool, knownHostsPath, knownHosts, oidcConfig, options, proxyAddress, tty)

	if qconn == nil {
		if status != 0 {
			log.Error().Msgf("could not setup transport for client: %s", err)
		}
		return status
	}

	roundTripper := &http3.RoundTripper{
		EnableDatagrams: true,
	}

	c, err := client.Dial(ctx, options, qconn, roundTripper, agentClient)
	if err != nil {
		log.Error().Msgf("could not dial %s: %s", options.CanonicalHostFormat(), err)
		return -1
	}
	if localTCPAddr != nil && remoteTCPAddr != nil {
		_, err := c.ForwardTCP(ctx, localTCPAddr, remoteTCPAddr)
		if err != nil {
			log.Error().Msgf("could not forward UDP: %s", err)
			return -1
		}
	}
	if localUDPAddr != nil && remoteUDPAddr != nil {
		_, err := c.ForwardUDP(ctx, localUDPAddr, remoteUDPAddr)
		if err != nil {
			log.Error().Msgf("could not forward UDP: %s", err)
			return -1
		}
	}

	err = c.RunSession(tty, *forwardSSHAgent, command...)
	switch sessionError := err.(type) {
	case client.ExitStatus:
		log.Info().Msgf("the process exited with status %d", sessionError.StatusCode)
		return sessionError.StatusCode
	case client.ExitSignal:
		log.Error().Msgf("the process exited with signal %s: %s", sessionError.Signal, sessionError.ErrorMessageUTF8)
		return -1
	default:
		log.Error().Msgf("an error was encountered when running the session: %s", sessionError)
		return -1
	}
}

func main() {
	os.Exit(mainWithStatusCode())
}
