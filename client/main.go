package main

import (
	// "bufio"
	// "bytes"
	// "context"
	"context"
	"crypto"
	"crypto/rsa"
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
	"golang.org/x/term"

	testdata "ssh3"
	ssh3 "ssh3/src"
	"ssh3/src/auth"
	ssh3Messages "ssh3/src/message"
	"ssh3/src/util"

	"github.com/golang-jwt/jwt/v5"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)


type windowSize struct {
    NRows    uint16
    NCols    uint16
    PixelWidth uint16
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
					log.Error().Msgf("reading message stopped on channel %d: %s", channel.ChannelID, err.Error())
				}
				return
			default:
				genericMessage, err = channel.NextMessage()
				if err != nil {
					err = fmt.Errorf("error when getting message on channel %d: %s", channel.ChannelID, err.Error())
					cancel(err)
					return
				}
				switch message := genericMessage.(type) {
				case *ssh3Messages.DataOrExtendedDataMessage:
					c.Write([]byte(message.Data))
				default:
					err = fmt.Errorf("unhandled message type on agent channel %d: %T", channel.ChannelID, message)
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
				log.Error().Msgf("ending agent forwarding on channel %d: %s", channel.ChannelID, err.Error())
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


func main() {
	// verbose := flag.Bool("v", false, "verbose")
	// quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	privKeyFile := flag.String("privkey", "", "private key file")
	passwordAuthentication := flag.Bool("use-password", false, "do classical password authentication")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	addRootCA := flag.String("add-root-ca", "", "add root CA from specified path")
	issuerUrl := flag.String("issuer-url", "https://accounts.google.com", "openid issuer url")
	oidcConfigFileName := flag.String("oidc-config", "", "oidc json config file containing the \"client_id\" and \"client_secret\" fields")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	doPKCE := flag.Bool("do-pkce", false, "if set perform PKCE challenge-response with oidc (currently not working)")
	forwardSSHAgent := flag.Bool("forward-agent", false, "if set, forwards ssh agent to be used with sshv2 connections on the remote host")
	forwardUDP := flag.String("forward-udp", "", "if set, takes a localport/remoteip@remoteport forwarding localhost@localport towards remoteip@remoteport")
	// enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	urls := flag.Args()


	if *verbose {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}

	var localUDPAddr *net.UDPAddr = nil
	var remoteUDPAddr *net.UDPAddr = nil
	if *forwardUDP != "" {
		array := strings.Split(*forwardUDP, "/")
		localPort, err := strconv.Atoi(array[0])
		if err != nil {
			log.Error().Msgf("could not convert %s to int: %s", array[0], err)
			return
		} else if localPort > 0xFFFF {
			log.Error().Msgf("UDP port too large %d", localPort)
			return
		}
		array = strings.Split(array[1], "@")
		remoteIP := net.ParseIP(array[0])
		if remoteIP == nil {
			log.Error().Msgf("could not parse IP %s", array[0])
			return
		}
		remotePort, err := strconv.Atoi(array[1])
		if err != nil {
			log.Error().Msgf("could not convert %s to int: %s", array[1], err)
			return
		} else if localPort > 0xFFFF {
			log.Error().Msgf("UDP port too large %d", remotePort)
			return
		}
		remoteUDPAddr = &net.UDPAddr{
			IP: remoteIP,
			Port: remotePort,
		}
		if len(remoteIP) == 4 {
			localUDPAddr = &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1),
				Port: localPort,
			}
		} else if len(remoteIP) == 16 {
			localUDPAddr = &net.UDPAddr{
				IP: net.IPv6loopback,
				Port: localPort,
			}
		} else {
			log.Error().Msgf("Unrecognized IP length %d", len(remoteIP))
			return
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// default to oidc if no password or privkey
	var err error = nil
	var oidcConfig *auth.OIDCConfig = nil
	var oidcConfigFile *os.File = nil
	if *privKeyFile == "" && !*passwordAuthentication && *oidcConfigFileName == "" {
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

	qconf.KeepAlivePeriod = 1*time.Second
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
		EnableDatagrams: true,
	}

	defer roundTripper.Close()

	for _, addr := range urls {
		log.Printf("GET %s", addr)
		parsedUrl, err := url.Parse(addr)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		req, err := http.NewRequest("CONNECT", addr, nil)
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}
		req.Proto = "ssh3"

		if *passwordAuthentication || (oidcConfig == nil && *privKeyFile == "") {
			fmt.Printf("password for %s:", parsedUrl.String())
			password, err := term.ReadPassword(int(syscall.Stdin))
		
			if err != nil {
				fmt.Fprintf(os.Stdin, "could not get password\n")
				return
			}
			
			req.SetBasicAuth(parsedUrl.User.Username(), string(password))
		} else if oidcConfig != nil {
			token, err := auth.Connect(context.Background(), oidcConfig, *issuerUrl, *doPKCE)
			if err != nil {
				log.Error().Msgf("could not get token: %s", err)
				return
			}
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		} else if *privKeyFile != "" {
			file, err := os.Open(*privKeyFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "could not open private key file:", err)
				return
			}
			keyBytes, err := io.ReadAll(file)
			if err != nil {
				fmt.Fprintln(os.Stderr, "could not load private key file:", err)
				return
			}
			key, err := ssh.ParseRawPrivateKey(keyBytes)
			if err != nil {
				fmt.Fprintln(os.Stderr, "could not parse private key file:", err)
				return
			}

			rsaKey := key.(crypto.PrivateKey).(*rsa.PrivateKey)

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": parsedUrl.User.Username(),
				"iat": jwt.NewNumericDate(time.Now()),
				"exp": jwt.NewNumericDate(time.Now().Add(10*time.Second)),
				"sub": "ssh3",
				"aud": "unused",
				"client_id": parsedUrl.User.Username(),
				"jti": "unused",
			})
			signedString, err := token.SignedString(rsaKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, "could not parse private key file:", err)
				return
			}
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", signedString))
		}

		conv, err := ssh3.EstablishNewClientConversation(ctx, req, roundTripper, 30000, 10)
		if err != nil {
			log.Error().Msgf("Could not open channel: %+v", err)
			os.Exit(-1)
		}


		channel, err := conv.OpenChannel("session", 30000, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not open channel: %+v", err)
			os.Exit(-1)
		}
		
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
						log.Error().Msgf("could not accept forwarding channel: %s", err.Error())
						return
					} else if forwardChannel.ChannelType() != "agent-connection" {
						log.Error().Msgf("unexpected server-initiated channel: %s", channel.ChannelType)
						return
					}
					log.Debug().Msg("new agent connection, forwarding")
					go func() {
						err = forwardAgent(ctx, forwardChannel)
						if err != nil {
							log.Error().Msgf("agent forwarding error: %s", err.Error())
							cancel()
						}
					}()
				}
			}()
		}

		windowSize, err := getWinsize()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not get window size: %+v", err)
			os.Exit(-1)
		}
		err = channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply: true,
				ChannelRequest: &ssh3Messages.PtyRequest{
					Term: os.Getenv("TERM"),
					CharWidth: uint64(windowSize.NCols),
					CharHeight: uint64(windowSize.NRows),
					PixelWidth: uint64(windowSize.PixelWidth),
					PixelHeight: uint64(windowSize.PixelHeight),
				},
			},
		)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could send pty request: %+v", err)
			return
		}

		err = channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply: true,
				ChannelRequest: &ssh3Messages.ShellRequest{},
			},
		)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could send shell request: %+v", err)
			return
		}

		fd := os.Stdin.Fd()

		oldState, err := term.MakeRaw(int(fd))
		if err != nil {
			log.Fatal().Msgf("%s", err)
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
			forwardings := make(map[*net.UDPAddr]ssh3.Channel)
			go func() {
				buf := make([]byte, 1500)
				for {
					n, addr, err := conn.ReadFromUDP(buf)
					if err != nil {
						log.Error().Msgf("could read on UDP socket: %s", err)
						return
					}
					channel, ok := forwardings[addr]
					if !ok {
						channel, err = conv.OpenUDPForwardingChannel(30000, 10, localUDPAddr, remoteUDPAddr)
						if err != nil {
							log.Error().Msgf("could open new UDP forwarding channel: %s", err)
							return
						}
						forwardings[addr] = channel

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

		defer conv.Close()
		defer term.Restore(int(fd), oldState)
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
						fmt.Fprintf(os.Stderr, "ssh3: process exited with status: %d\n", requestMessage.ExitStatus)
						return
					case *ssh3Messages.ExitSignalRequest:
						fmt.Fprintf(os.Stderr, "ssh3: process exited with signal: %s: %s\n", requestMessage.SignalNameWithoutSig, requestMessage.ErrorMessageUTF8)
						return
				}
			case *ssh3Messages.DataOrExtendedDataMessage:
				switch message.DataType {
				case ssh3Messages.SSH_EXTENDED_DATA_NONE:
					_, err = os.Stdout.Write([]byte(message.Data))
					if err != nil {
						log.Fatal().Msgf("%s", err)
					}
				}
			}
		}

	}
}

