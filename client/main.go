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
	"net/http"
	"net/url"
	"os"
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
	// "github.com/quic-go/quic-go/logging"
	// "github.com/quic-go/quic-go/qlog"
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


func main() {
	// verbose := flag.Bool("v", false, "verbose")
	// quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	privKeyFile := flag.String("privkey", "", "private key file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	issuerUrl := flag.String("issuer-url", "https://accounts.google.com", "openid issuer url")
	oidcConfigFile := flag.String("oidc-config", "", "oidc json config file containing the \"client_id\" and \"client_secret\" fields")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	// enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()
	urls := flag.Args()


	if *verbose {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))
	}


	var oidcConfig *auth.OIDCConfig = nil 
	if *oidcConfigFile != "" {
		configFile, err := os.Open(*oidcConfigFile)
		if err != nil {
			log.Error().Msgf("could not open oidc config file %s: %s", *oidcConfigFile, err.Error())
			return
		}
		oidcConfig = new(auth.OIDCConfig)
		data, err := io.ReadAll(configFile)
		if err = json.Unmarshal(data, oidcConfig); err != nil {
			log.Error().Msgf("could not load oidc config file: %s", err.Error())
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
	testdata.AddRootCA(pool)

	var qconf quic.Config

	qconf.KeepAlivePeriod = 1*time.Second
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
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

		if *privKeyFile != "" {
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
		} else if *oidcConfigFile != "" {
			token, err := auth.Connect(context.Background(), oidcConfig, *issuerUrl)
			if err != nil {
				log.Error().Msgf("could not get token:", err)
				return
			}
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		} else {
			fmt.Printf("password for %s:", parsedUrl.String())
			password, err := term.ReadPassword(int(syscall.Stdin))
		
			if err != nil {
				fmt.Fprintf(os.Stdin, "could not get password\n")
				return
			}
			
			req.SetBasicAuth(parsedUrl.User.Username(), string(password))
		}

		rsp, err := roundTripper.RoundTripOpt(req, http3.RoundTripOpt{DontCloseRequestStream: true})
		if err != nil {
			log.Fatal().Msgf("%s", err)
		}

		if rsp.StatusCode == 200 {

			str := rsp.Body.(http3.HTTPStreamer).HTTPStream()
			conn := rsp.Body.(http3.Hijacker).StreamCreator()
			conv := ssh3.NewClientConversation(str, roundTripper, conn, 30000)

			channel, err := conv.OpenChannel("session", 30000)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Could not open channel: %+v", err)
				os.Exit(-1)
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
				buf := make([]byte, channel.MaxPacketSize)
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
			
			defer str.Close()
			defer term.Restore(int(fd), oldState)

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

		} else {
			fmt.Println("Failure: got response:", rsp.Status)
		}
	}
}

