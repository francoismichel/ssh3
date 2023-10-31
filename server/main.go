package main

import (
	// "bufio"
	// "context"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	_ "net/http/pprof"

	"github.com/creack/pty"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	// "github.com/quic-go/quic-go/logging"
	// "github.com/quic-go/quic-go/qlog"

	testdata "ssh3"
	ssh3 "ssh3/src"
	ssh3Messages "ssh3/src/message"
)

var signals = map[string]os.Signal {
	"SIGABRT":    syscall.Signal(0x6),
	"SIGALRM":    syscall.Signal(0xe),
	"SIGBUS":     syscall.Signal(0x7),
	"SIGCHLD":    syscall.Signal(0x11),
	"SIGCLD":     syscall.Signal(0x11),
	"SIGCONT":    syscall.Signal(0x12),
	"SIGFPE":     syscall.Signal(0x8),
	"SIGHUP":     syscall.Signal(0x1),
	"SIGILL":     syscall.Signal(0x4),
	"SIGINT":     syscall.Signal(0x2),
	"SIGIO":      syscall.Signal(0x1d),
	"SIGIOT":     syscall.Signal(0x6),
	"SIGKILL":    syscall.Signal(0x9),
	"SIGPIPE":    syscall.Signal(0xd),
	"SIGPOLL":    syscall.Signal(0x1d),
	"SIGPROF":    syscall.Signal(0x1b),
	"SIGPWR":     syscall.Signal(0x1e),
	"SIGQUIT":    syscall.Signal(0x3),
	"SIGSEGV":    syscall.Signal(0xb),
	"SIGSTKFLT":  syscall.Signal(0x10),
	"SIGSTOP":    syscall.Signal(0x13),
	"SIGSYS":     syscall.Signal(0x1f),
	"SIGTERM":    syscall.Signal(0xf),
	"SIGTRAP":    syscall.Signal(0x5),
	"SIGTSTP":    syscall.Signal(0x14),
	"SIGTTIN":    syscall.Signal(0x15),
	"SIGTTOU":    syscall.Signal(0x16),
	"SIGUNUSED":  syscall.Signal(0x1f),
	"SIGURG":     syscall.Signal(0x17),
	"SIGUSR1":    syscall.Signal(0xa),
	"SIGUSR2":    syscall.Signal(0xc),
	"SIGVTALRM":  syscall.Signal(0x1a),
	"SIGWINCH":   syscall.Signal(0x1c),
	"SIGXCPU":    syscall.Signal(0x18),
	"SIGXFSZ":    syscall.Signal(0x19),
}

type channelType uint64

const ( 
	PTY = channelType(iota)
	X11
	SHELL
	EXEC
	SUBSYSTEM
	

)

var channelTypes = make(map[*ssh3.Channel]channelType)

type runningPty struct {
	stdin io.Writer
	stdout io.Reader
	stderr io.Reader
	process *os.Process
}

var conversations = make(map[quic.Stream]*ssh3.Conversation)
var runningPtys = make(map[*ssh3.Channel]*runningPty)

func setWinsize(f *os.File, charWidth, charHeight, pixWidth, pixHeight uint64) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(charHeight), uint16(charWidth), uint16(pixWidth), uint16(pixHeight)})))
}

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}


func newPtyReq(channel *ssh3.Channel, request ssh3Messages.PtyRequest, wantReply bool) error {
	cmd := exec.Command("bash")
	cmd.Env = append(cmd.Env, fmt.Sprintf("TERM=%s", request.Term))


	fmt.Println("PTY REQUEST", request, channel.MaxPacketSize)

	f, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(request.CharHeight), Cols: uint16(request.CharWidth), X: uint16(request.PixelWidth), Y: uint16(request.PixelHeight)})
	if err != nil {
		panic(err)
	}
	setWinsize(f, request.CharWidth, request.CharHeight, request.PixelWidth, request.PixelHeight)

	channelTypes[channel] = PTY
	runningPtys[channel] = &runningPty{
		stdin: f,
		stdout: f,
		stderr: f,
		process: cmd.Process,
	}

	go func() {
		
		type readResult struct {
			data []byte
			err error
		}

		buf := make([]byte, channel.MaxPacketSize)
		

		defer func() {
			err := cmd.Wait()
			exitstatus := uint64(0)
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					exitstatus = uint64(exitError.ExitCode())
				}
			}

			channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
				WantReply: false,
				ChannelRequest: &ssh3Messages.ExitStatusRequest{ ExitStatus: exitstatus },
			})
		}()

		for {
			n, err := f.Read(buf)
			_, err2 := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err2 != nil {
				fmt.Fprintf(os.Stderr, "could not write the pty's output in an SSH message: %+v\n", err)
				return
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not read the pty's output: %+v\n", err)
				return
			}
		}
	}()
	return nil
}

func newX11Req(channel *ssh3.Channel, request ssh3Messages.X11Request, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newShellReq(channel *ssh3.Channel, request ssh3Messages.ShellRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newExecReq(channel *ssh3.Channel, request ssh3Messages.ExecRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newSubsystemReq(channel *ssh3.Channel, request ssh3Messages.SubsystemRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newWindowChangeReq(channel *ssh3.Channel, request ssh3Messages.WindowChangeRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newSignalReq(channel *ssh3.Channel, request ssh3Messages.SignalRequest, wantReply bool) error {
	channelType, ok := channelTypes[channel]
	if !ok {
		return fmt.Errorf("could not find channel type for channel %d (conv %d)", channel.ChannelID, channel.ConversationID)
	}
	switch channelType {
	case PTY:
		runningPty, ok := runningPtys[channel]
		if !ok {
			return fmt.Errorf("could not find runing PTY for channel %d (conv %d)", channel.ChannelID, channel.ConversationID)
		}
		signal, ok := signals["SIG" + request.SignalNameWithoutSig]
		if !ok {
			return fmt.Errorf("unhandled signal SIG%s", request.SignalNameWithoutSig)
		}
		runningPty.process.Signal(signal)
	default:
		return fmt.Errorf("channel type %d not implemented", channelType)
	}
	return nil
}

func newExitStatusReq(channel *ssh3.Channel, request ssh3Messages.ExitStatusRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newExitSignalReq(channel *ssh3.Channel, request ssh3Messages.ExitSignalRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newDataReq(channel *ssh3.Channel, request ssh3Messages.DataOrExtendedDataMessage) error {
	channelType, ok := channelTypes[channel]
	if !ok {
		return fmt.Errorf("could not find channel type for channel %d (conv %d)", channel.ChannelID, channel.ConversationID)
	}
	switch channelType {
	case PTY:
		fmt.Println("handle new data req")
		runningPty, ok := runningPtys[channel]
		if !ok {
			return fmt.Errorf("could not find running PTY for channel %d (conv %d)", channel.ChannelID, channel.ConversationID)
		}
		switch request.DataType {
		case ssh3Messages.SSH_EXTENDED_DATA_NONE:
			runningPty.stdin.Write([]byte(request.Data))
		default:
			return fmt.Errorf("extended data type forbidden server PTY")
		}
	default:
		return fmt.Errorf("channel type %d not implemented", channelType)
	}
	return nil
}

func main() {
	// defer profile.Start().Stop()
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// runtime.SetBlockProfileRate(1)

	// verbose := flag.Bool("v", false, "verbose")
	bs := binds{}
	flag.Var(&bs, "bind", "bind to")
	// enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	flag.Parse()


	if len(bs) == 0 {
		bs = binds{"localhost:6121"}
	}

	quicConf := &quic.Config{}
	// if *enableQlog {
	// 	quicConf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) logging.ConnectionTracer {
	// 		filename := fmt.Sprintf("server_%x.qlog", connID)
	// 		f, err := os.Create(filename)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 		log.Printf("Creating qlog file %s.\n", filename)
	// 		return qlog.NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), p, connID)
	// 	}
	// }


	var wg sync.WaitGroup
	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			var err error

			server := http3.Server{
				Handler:    nil,
				Addr:       bCap,
				QuicConfig: quicConf,
			}
			certFile, keyFile := testdata.GetCertificatePaths()

			mux := http.NewServeMux()
			ssh3Server := ssh3.NewServer(30000, &server, func(conv *ssh3.Conversation) error {
				for {
					channel, err := conv.AcceptChannel(context.Background())
					if err != nil {
						return err
					}
					go func() {
						defer channel.Close()
						for {
							genericMessage, err := channel.NextMessage()
							if err != nil {
								fmt.Printf("error when getting message: %+v", err)
								return
							}
							
							switch message := genericMessage.(type) {
								case *ssh3Messages.ChannelRequestMessage:
									switch requestMessage := message.ChannelRequest.(type) {
										case *ssh3Messages.PtyRequest:
											err = newPtyReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.X11Request:
											err = newX11Req(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.ShellRequest:
											err = newShellReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.ExecRequest:
											err = newExecReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.SubsystemRequest:
											err = newSubsystemReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.WindowChangeRequest:
											err = newWindowChangeReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.SignalRequest:
											err = newSignalReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.ExitStatusRequest:
											err = newExitStatusReq(channel, *requestMessage, message.WantReply)
										case *ssh3Messages.ExitSignalRequest:
											err = newExitSignalReq(channel, *requestMessage, message.WantReply)
									}
								case *ssh3Messages.DataOrExtendedDataMessage:
									err = newDataReq(channel, *message)
							}
							if err != nil {
								fmt.Fprintf(os.Stderr, "error while processing message: %+V", genericMessage)
								return
							}
						}
					}()
				}
			})
			ssh3Handler := ssh3Server.GetHTTPHandlerFunc()
			mux.HandleFunc("/ssh3-pty", ssh3Handler)
			server.Handler = mux
			err = server.ListenAndServeTLS(certFile, keyFile)
			
			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
