package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"syscall"
	"unsafe"

	_ "net/http/pprof"

	"github.com/caddyserver/certmagic"
	"github.com/creack/pty"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	ssh3 "github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/server_auth"
	util "github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"
)

var signals = map[string]os.Signal{
	"SIGABRT":   syscall.Signal(0x6),
	"SIGALRM":   syscall.Signal(0xe),
	"SIGBUS":    syscall.Signal(0x7),
	"SIGCHLD":   syscall.Signal(0x11),
	"SIGCLD":    syscall.Signal(0x11),
	"SIGCONT":   syscall.Signal(0x12),
	"SIGFPE":    syscall.Signal(0x8),
	"SIGHUP":    syscall.Signal(0x1),
	"SIGILL":    syscall.Signal(0x4),
	"SIGINT":    syscall.Signal(0x2),
	"SIGIO":     syscall.Signal(0x1d),
	"SIGIOT":    syscall.Signal(0x6),
	"SIGKILL":   syscall.Signal(0x9),
	"SIGPIPE":   syscall.Signal(0xd),
	"SIGPOLL":   syscall.Signal(0x1d),
	"SIGPROF":   syscall.Signal(0x1b),
	"SIGPWR":    syscall.Signal(0x1e),
	"SIGQUIT":   syscall.Signal(0x3),
	"SIGSEGV":   syscall.Signal(0xb),
	"SIGSTKFLT": syscall.Signal(0x10),
	"SIGSTOP":   syscall.Signal(0x13),
	"SIGSYS":    syscall.Signal(0x1f),
	"SIGTERM":   syscall.Signal(0xf),
	"SIGTRAP":   syscall.Signal(0x5),
	"SIGTSTP":   syscall.Signal(0x14),
	"SIGTTIN":   syscall.Signal(0x15),
	"SIGTTOU":   syscall.Signal(0x16),
	"SIGUNUSED": syscall.Signal(0x1f),
	"SIGURG":    syscall.Signal(0x17),
	"SIGUSR1":   syscall.Signal(0xa),
	"SIGUSR2":   syscall.Signal(0xc),
	"SIGVTALRM": syscall.Signal(0x1a),
	"SIGWINCH":  syscall.Signal(0x1c),
	"SIGXCPU":   syscall.Signal(0x18),
	"SIGXFSZ":   syscall.Signal(0x19),
}

type channelType uint64

const (
	LARVAL = channelType(iota)
	OPEN
)

type openPty struct {
	pty     *os.File // pty used by the server/user to communicate with the running process
	tty     *os.File // tty used by the running process to communicate with the server/user
	winSize *pty.Winsize
	term    string
}

type runningCommand struct {
	exec.Cmd
	stdoutR io.Reader
	stderrR io.Reader
	stdinW  io.Writer
}

type runningSession struct {
	channelState        channelType
	pty                 *openPty
	runningCmd          *runningCommand
	authAgentSocketPath string
}

// var runningSessions = make(map[ssh3.Channel]*runningSession)
var runningSessions = util.NewSyncMap[ssh3.Channel, *runningSession]()

func setWinsize(f *os.File, charWidth, charHeight, pixWidth, pixHeight uint64) {
	syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&struct{ h, w, x, y uint16 }{uint16(charHeight), uint16(charWidth), uint16(pixWidth), uint16(pixHeight)})))
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

func setupEnv(user *unix_util.User, runningCommand *runningCommand, authAgentSocketPath string) {
	// TODO: set the environment like in do_setup_env of https://github.com/openssh/openssh-portable/blob/master/session.c
	runningCommand.Cmd.Env = append(runningCommand.Cmd.Env,
		fmt.Sprintf("HOME=%s", user.Dir),
		fmt.Sprintf("USER=%s", user.Username),
		fmt.Sprintf("PATH=%s", "/usr/bin:/bin:/usr/sbin:/sbin"),
	)
	if authAgentSocketPath != "" {
		runningCommand.Cmd.Env = append(runningCommand.Cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", authAgentSocketPath))
	}
}

func forwardUDPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.UDPConn) {
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
			if errors.Is(err, io.EOF) {
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
			if err != nil && !errors.Is(err, io.EOF) {
				log.Error().Msgf("could read data on TCP socket: %s", err)
				return
			}
			_, errWrite := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if errWrite != nil {
				switch quicErr := errWrite.(type) {
				case *quic.StreamError:
					if quicErr.Remote && quicErr.ErrorCode == 42 {
						log.Info().Msgf("writing was canceled by the remote, closing the socket")
					} else {
						log.Error().Msgf("unhandled quic stream error: %+v", quicErr)
					}
				default:
					log.Error().Msgf("could send data on channel: %s", errWrite)
				}
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
		}
	}()
}

func forwardReverseTCPInBackground(ctx context.Context, channel ssh3.Channel, conn *net.TCPConn) {
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
				log.Info().Msgf("eof on reverse-tcp-forwarding channel %d", channel.ChannelID())
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

}

func execCmdInBackground(channel ssh3.Channel, openPty *openPty, user *unix_util.User, runningCommand *runningCommand, authAgentSocketPath string) error {
	setupEnv(user, runningCommand, authAgentSocketPath)
	if openPty != nil {
		err := unix_util.StartWithSizeAndPty(&runningCommand.Cmd, openPty.winSize, openPty.pty, openPty.tty)
		if err != nil {
			return err
		}
	} else {
		err := runningCommand.Start()
		if err != nil {
			return err
		}
	}

	go func() {

		type readResult struct {
			data []byte
			err  error
		}

		stdoutChan := make(chan readResult, 1)
		stderrChan := make(chan readResult, 1)
		execResultChan := make(chan error, 1)
		execExitStatus := uint64(0)

		readStdout := func() {
			defer close(stdoutChan)
			if runningCommand.stdoutR != nil {
				for {
					buf := make([]byte, channel.MaxPacketSize())
					n, err := runningCommand.stdoutR.Read(buf)
					out := make([]byte, n)
					copy(out, buf[:n])
					stdoutChan <- readResult{data: out, err: err}
					if err != nil {
						return
					}
				}
			}
		}
		readStderr := func() {
			defer close(stderrChan)
			if runningCommand.stderrR != nil {
				for {
					buf := make([]byte, channel.MaxPacketSize())
					n, err := runningCommand.stderrR.Read(buf)
					out := make([]byte, n)
					copy(out, buf[:n])
					stderrChan <- readResult{data: out, err: err}
					if err != nil {
						return
					}
				}
			}
		}

		go readStdout()
		go readStderr()
		go func() {
			execResultChan <- runningCommand.Wait()
			close(execResultChan)
		}()

		for {
			select {
			case stdoutResult, ok := <-stdoutChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					stdoutChan = nil
				} else {
					buf, err := stdoutResult.data, stdoutResult.err
					// an error could be returned but still with relevant data, so first send the data
					_, err2 := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
					if err2 != nil {
						log.Error().Msgf("could not write the pty's output in an SSH message: %+v\n", err)
						return
					}
					if err != nil && !errors.Is(err, io.EOF) {
						log.Info().Msgf("could not read the pty's output, it might have been closed by the running process: %s", err)
					}
				}

			case stderrResult, ok := <-stderrChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					stderrChan = nil
				} else {
					buf, err := stderrResult.data, stderrResult.err
					_, err2 := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_STDERR)
					if err2 != nil {
						log.Error().Msgf("could not write the pty's output in an SSH message: %+v\n", err)
						return
					}
					if err != nil && !errors.Is(err, io.EOF) {
						log.Info().Msgf("could not read the pty's error output, it might have been closed by the running process: %s", err)
					}
				}

			case err, ok := <-execResultChan:
				if !ok {
					// disable the channel: a select on a nil is always blocking
					execResultChan = nil
				} else {
					execExitStatus = uint64(0)
					if err != nil {
						if exitError, ok := err.(*exec.ExitError); ok {
							execExitStatus = uint64(exitError.ExitCode())
						}
					}
				}
			}
			if stdoutChan == nil && stderrChan == nil && execResultChan == nil {
				err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
					WantReply:      false,
					ChannelRequest: &ssh3Messages.ExitStatusRequest{ExitStatus: execExitStatus},
				})
				if err != nil {
					log.Error().Msgf("Could not send exit status message to the peer: %s", err)
				}
				// both channels are closed, nothing else to do, return
				return
			}
		}
	}()
	return nil
}

func newPtyReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.PtyRequest, wantReply bool) error {
	var session *runningSession
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("internal error: cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request new pty on already established session")
	}

	if session.pty != nil {
		return fmt.Errorf("cannot request new pty on a channel with an already existing pty")
	}
	winSize := &pty.Winsize{Rows: uint16(request.CharHeight), Cols: uint16(request.CharWidth), X: uint16(request.PixelWidth), Y: uint16(request.PixelHeight)}
	pty, tty, err := pty.Open()
	if err != nil {
		return err
	}

	setWinsize(pty, request.CharWidth, request.CharHeight, request.PixelWidth, request.PixelHeight)

	session.pty = &openPty{
		pty:     pty,
		tty:     tty,
		term:    request.Term,
		winSize: winSize,
	}

	return nil
}

func newX11Req(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.X11Request, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newCommand(user *unix_util.User, channel ssh3.Channel, loginShell bool, command string, args ...string) error {
	var session *runningSession
	session, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("internal error: cannot find session for current channel")
	}

	if session.channelState != LARVAL {
		return fmt.Errorf("cannot request new shell on already established session")
	}

	env := ""
	if session.pty != nil {
		env = fmt.Sprintf("TERM=%s", session.pty.term)
	}

	var stdoutR, stderrR, stdinR io.Reader
	var stdoutW, stderrW, stdinW io.Writer
	var err error = nil
	var cmd *exec.Cmd

	if session.pty != nil {
		stdoutW = session.pty.tty
		stderrW = session.pty.tty
		stdinR = session.pty.tty

		stdoutR = session.pty.pty
		stderrR = nil
		stdinW = session.pty.pty
		cmd, _, _, _, err = user.CreateCommand(env, stdoutW, stderrW, stdinR, loginShell, command, args...)
	} else {
		stdoutR, stdoutW, err = os.Pipe()
		if err != nil {
			return err
		}
		stderrR, stderrW, err = os.Pipe()
		if err != nil {
			return err
		}
		stdinR, stdinW, err = os.Pipe()
		if err != nil {
			return err
		}
		cmd, stdoutR, stderrR, stdinW, err = user.CreateCommandPipeOutput(env, loginShell, command, args...)
	}

	if err != nil {
		return err
	}

	runningCommand := &runningCommand{
		Cmd:     *cmd,
		stdoutR: stdoutR,
		stderrR: stderrR,
		stdinW:  stdinW,
	}

	session.runningCmd = runningCommand

	session.channelState = OPEN

	return execCmdInBackground(channel, session.pty, user, session.runningCmd, session.authAgentSocketPath)
}

func newShellReq(user *unix_util.User, channel ssh3.Channel, wantReply bool) error {
	return newCommand(user, channel, true, user.Shell)
}

// similar behaviour to OpenSSH; exec requests are just pasted in the user's shell
func newCommandInShellReq(user *unix_util.User, channel ssh3.Channel, wantReply bool, command string) error {
	return newCommand(user, channel, false, user.Shell, "-c", command)
}

func newSubsystemReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.SubsystemRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newWindowChangeReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.WindowChangeRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newSignalReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.SignalRequest, wantReply bool) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.channelState == LARVAL {
		return fmt.Errorf("cannot send signal for channel in LARVAL state (channel %d, conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	switch channel.ChannelType() {
	case "session":
		if runningSession.runningCmd == nil {
			return fmt.Errorf("there is no running command on Channel %d (conv %d) to feed the received data", channel.ChannelID(), channel.ConversationID())
		}
		signal, ok := signals["SIG"+request.SignalNameWithoutSig]
		if !ok {
			return fmt.Errorf("unhandled signal SIG%s", request.SignalNameWithoutSig)
		}
		runningSession.runningCmd.Process.Signal(signal)
	default:
		return fmt.Errorf("channel type %s not implemented", channel.ChannelType())
	}
	return nil
}

func newExitStatusReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.ExitStatusRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func newExitSignalReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.ExitSignalRequest, wantReply bool) error {
	return fmt.Errorf("%T not implemented", request)
}

func handleUDPForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.UDPForwardingChannelImpl) error {
	// TODO: currently, the rights for socket creation are not checked. The socket is opened with the process's uid and gid
	// Not sure how to handled that in go since we cannot temporarily change the uid/gid without potentially impacting every
	// other goroutine
	conn, err := net.DialUDP("udp", nil, channel.RemoteAddr)
	if err != nil {
		return err
	}
	forwardUDPInBackground(ctx, channel, conn)
	return nil
}

func handleTCPForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.TCPForwardingChannelImpl) error {
	// TODO: currently, the rights for socket creation are not checked. The socket is opened with the process's uid and gid
	// Not sure how to handled that in go since we cannot temporarily change the uid/gid without potentially impacting every
	// other goroutine
	conn, err := net.DialTCP("tcp", nil, channel.RemoteAddr)
	if err != nil {
		return err
	}
	forwardTCPInBackground(ctx, channel, conn)
	return nil
}

func handleTCPReverseForwardingChannel(ctx context.Context, user *unix_util.User, conv *ssh3.Conversation, channel *ssh3.TCPReverseForwardingChannelImpl) error {
	conn, err := net.ListenTCP("tcp", channel.LocalAddr)
	if err != nil {
		log.Error().Msgf("could listen on TCP socket: %s", err)
		return nil
	}

	go func() {
		for {
			conn, err := conn.AcceptTCP()
			if err != nil {
				log.Error().Msgf("could read on UDP socket: %s", err)
				return
			}

			forwardingChannel, err := conv.OpenTCPReverseForwardingChannel(30000, 10, channel.RemoteAddr)
			if err != nil {
				log.Error().Msgf("could not open new TCP reverse forwarding channel: %s", err)
				return
			}
			forwardReverseTCPInBackground(ctx, forwardingChannel, conn)
		}
	}()
	return nil
}

func newDataReq(user *unix_util.User, channel ssh3.Channel, request ssh3Messages.DataOrExtendedDataMessage) error {
	runningSession, ok := runningSessions.Get(channel)
	if !ok {
		return fmt.Errorf("could not find running session for channel %d (conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	if runningSession.channelState == LARVAL {
		return fmt.Errorf("cannot receive data for channel in LARVAL state (channel %d, conv %d)", channel.ChannelID(), channel.ConversationID())
	}

	switch channel.ChannelType() {
	case "session":
		if runningSession.runningCmd == nil {
			return fmt.Errorf("there is no running command on Channel %d (conv %d) to feed the received data", channel.ChannelID(), channel.ConversationID())
		}
		switch request.DataType {
		case ssh3Messages.SSH_EXTENDED_DATA_NONE:
			runningSession.runningCmd.stdinW.Write([]byte(request.Data))
		default:
			return fmt.Errorf("extended data type forbidden server PTY")
		}
	default:
		return fmt.Errorf("channel type %s not implemented", channel.ChannelType())
	}
	return nil
}

func handleAuthAgentSocketConn(conn net.Conn, conversation *ssh3.Conversation) {
	channel, err := conversation.OpenChannel("agent-connection", 30000, 10)
	if err != nil {
		log.Error().Msgf("could not open channel from server: %s", err.Error())
		return
	}
	go func() {
		defer channel.Close()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Info().Msgf("could not read data socket %d: %s", channel.ChannelID(), err.Error())
				return
			}
			_, err = channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE)
			if err != nil {
				log.Info().Msgf("could not write data on agent channel %d: %s", channel.ChannelID(), err.Error())
				return
			}
		}
	}()
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			log.Error().Msgf("could not get data from channel %d: %s", channel.ChannelID(), err.Error())
			return
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			_, err := conn.Write([]byte(message.Data))
			if err != nil {
				log.Error().Msgf("could not write data to channel %d: %s", channel.ChannelID(), err.Error())
				return
			}
		default:
			log.Error().Msgf("unhandled message type on agent channel %T", message)
			return
		}
	}
}

func listenAndAcceptAuthSockets(cancel context.CancelCauseFunc, conversation *ssh3.Conversation, listener net.Listener, maxSSHPacketSize uint64) {
	defer cancel(nil)
	defer listener.Close()
	for {
		log.Debug().Msg("waiting for new agent connections to forward")
		conn, err := listener.Accept()
		if err != nil {
			log.Error().Msgf("error while listening for agent connections: %s", err.Error())
			cancel(err)
			return
		}
		// new ssh agent client
		go handleAuthAgentSocketConn(conn, conversation)
	}
}

func openAgentSocketAndForwardAgent(parent context.Context, conv *ssh3.Conversation, user *unix_util.User) (string, error) {
	ctx, cancel := context.WithCancelCause(parent)
	sockPath, err := unix_util.NewUnixSocketPath()
	if err != nil {
		return "", err
	}

	var listener net.ListenConfig
	agentSock, err := listener.Listen(ctx, "unix", sockPath)
	if err != nil {
		log.Error().Msgf("could not listen on agent socket: %s", err.Error())
		return "", err
	}

	sockDir := path.Dir(sockPath)
	err = os.Chown(sockDir, int(user.Uid), int(user.Gid))
	if err != nil {
		log.Error().Msgf("could chown the directory of the listening socket at %s: %s", sockPath, err.Error())
		return "", err
	}
	err = os.Chown(sockPath, int(user.Uid), int(user.Gid))
	if err != nil {
		log.Error().Msgf("could chown the listening socket at %s: %s", sockPath, err.Error())
		return "", err
	}

	go listenAndAcceptAuthSockets(cancel, conv, agentSock, 30000)
	return sockPath, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

type autogenCertificates []string

func (i *autogenCertificates) String() string {
	return fmt.Sprint(*i)
}

func (i *autogenCertificates) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func ServerMain() int {
	bindAddr := flag.String("bind", "[::]:443", "the address:port pair to listen to, e.g. 0.0.0.0:443")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	displayVersion := flag.Bool("version", false, "if set, displays the software version on standard output and exit")
	urlPath := flag.String("url-path", "/ssh3-term", "the secret URL path on which the ssh3 server listens")
	generateSelfSignedCert := flag.Bool("generate-selfsigned-cert", false, "if set, generates a self-self-signed cerificate and key "+
		"that will be stored at the paths indicated by the -cert and -key args (they must not already exist)")
	certPath := flag.String("cert", "./cert.pem", "the filename of the server certificate (or fullchain)")
	keyPath := flag.String("key", "./priv.key", "the filename of the certificate private key")
	var autogenCertificates autogenCertificates
	flag.Var(&autogenCertificates, "generate-public-cert", "Automatically produce and use a valid public certificate using"+
		"Let's Encrypt for the provided domain name. The flag can be used several times to generate several certificates."+
		"If certificates have already been generated previously using this flag, "+
		"they will simply be reused without being regenerated. The public certificates are automatically renewed as long as the "+
		"server is running. Automatically-generated IP public certificates are not available yet.")
	enablePasswordLogin := false
	if unix_util.PasswordAuthAvailable() {
		flag.BoolVar(&enablePasswordLogin, "enable-password-login", false, "if set, enable password authentication (disabled by default)")
	}
	flag.Parse()

	if *displayVersion {
		fmt.Fprintln(os.Stdout, filepath.Base(os.Args[0]), "version", ssh3.GetCurrentSoftwareVersion())
		return 0
	}

	if !enablePasswordLogin {
		fmt.Fprintln(os.Stderr, "password login is disabled")
	}

	certPathExists := fileExists(*certPath)
	keyPathExists := fileExists(*keyPath)

	// handle bad case where one of the cert or key path is valid but not the other
	badCertificatesConf := (certPathExists && !keyPathExists) ||
		(!certPathExists && keyPathExists) ||
		(!certPathExists && !keyPathExists && !*generateSelfSignedCert && len(autogenCertificates) == 0) // no certificate available whatsoever

	if badCertificatesConf {
		if !certPathExists {
			fmt.Fprintf(os.Stderr, "the \"%s\" certificate file does not exist\n", *certPath)
		}
		if !keyPathExists {
			fmt.Fprintf(os.Stderr, "the \"%s\" certificate private key file does not exist\n", *keyPath)
		}
		fmt.Fprintln(os.Stderr, "No certificate available for the QUIC connection.")
		fmt.Fprintln(os.Stderr, "If you have no certificate and want a security comparable to traditional SSH host keys, "+
			"you can generate a self-signed certificate using the -generate-selfsigned-cert arg or using the following script:")
		fmt.Fprintln(os.Stderr, "https://github.com/francoismichel/ssh3/blob/main/generate_openssl_selfsigned_certificate.sh")
		return -1
	} else if *generateSelfSignedCert {
		if certPathExists {
			fmt.Fprintf(os.Stderr, "asked for generating a certificate but the \"%s\" file already exists\n", *certPath)
		}
		if keyPathExists {
			fmt.Fprintf(os.Stderr, "asked for generating a private key but the \"%s\" file already exists\n", *keyPath)
		}
		if certPathExists || keyPathExists {
			return -1
		}
		pubkey, privkey, err := util.GenerateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate private key: %s\n", err)
			return -1
		}
		cert, err := util.GenerateCert(privkey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate certificate: %s\n", err)
			return -1
		}

		err = util.DumpCertAndKeyToFiles(cert, pubkey, privkey, *certPath, *keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not save certificate and key to files: %s\n", err)
			return -1
		}

		certPathExists = true
		keyPathExists = true
	}

	if *verbose {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		util.ConfigureLogger("debug")
	} else {
		util.ConfigureLogger(os.Getenv("SSH3_LOG_LEVEL"))

		logFileName := os.Getenv("SSH3_LOG_FILE")
		if logFileName == "" {
			logFileName = "/var/log/ssh3.log"
		}
		logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open log file %s: %s\n", logFileName, err.Error())
			return -1
		}
		log.Logger = log.Output(logFile)
	}

	tlsConfig := &tls.Config{}
	if len(autogenCertificates) > 0 {
		var zapLevel zapcore.Level
		switch zerolog.GlobalLevel() {
		case zerolog.TraceLevel:
			fallthrough
		case zerolog.DebugLevel:
			zapLevel = zap.DebugLevel
		case zerolog.InfoLevel:
			zapLevel = zap.InfoLevel
		case zerolog.WarnLevel:
			zapLevel = zap.WarnLevel
		case zerolog.ErrorLevel:
			zapLevel = zap.ErrorLevel
		}
		certmagic.Default.Logger = zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			os.Stderr,
			zapLevel,
		))
		certmagic.Default.Logger = certmagic.Default.Logger.Named("github.com/caddyserver/certmagic")

		var err error
		fmt.Fprintln(os.Stderr, "Generate public certificates...")
		tlsConfig, err = certmagic.TLS(autogenCertificates)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not generate public certificates: %s\n", err)
			return -1
		}
		fmt.Fprintln(os.Stderr, "Successfully generated public certificates")
	}

	if certPathExists && keyPathExists {
		certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not load -cert and -key pair: %s\n", err)
			return -1
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	}

	log.Debug().Msgf("version %s", ssh3.GetCurrentSoftwareVersion())

	quicConf := &quic.Config{
		Allow0RTT: true,
	}

	var err error

	server := http3.Server{
		Handler:         nil,
		Addr:            *bindAddr,
		QuicConfig:      quicConf,
		EnableDatagrams: true,
		TLSConfig:       tlsConfig,
	}

	mux := http.NewServeMux()
	ssh3Server := ssh3.NewServer(30000, 10, &server, func(authenticatedUsername string, conv *ssh3.Conversation) error {
		authenticatedUser, err := unix_util.GetUser(authenticatedUsername)
		if err != nil {
			return err
		}
		for {
			channel, err := conv.AcceptChannel(conv.Context())
			if err != nil {
				return err
			}

			switch c := channel.(type) {
			case *ssh3.UDPForwardingChannelImpl:
				handleUDPForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			case *ssh3.TCPForwardingChannelImpl:
				handleTCPForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			case *ssh3.TCPReverseForwardingChannelImpl:
				handleTCPReverseForwardingChannel(conv.Context(), authenticatedUser, conv, c)
			default:
				runningSessions.Insert(channel, &runningSession{
					channelState: LARVAL,
					pty:          nil,
					runningCmd:   nil,
				})
				go func() {
					// handle the main sessionChannel, once it ends, the whole conversation ends
					defer channel.Close()
					defer conv.Close()
					for {
						genericMessage, err := channel.NextMessage()
						if errors.Is(err, net.ErrClosed) {
							log.Debug().Msgf("the connection was closed by the application: %s", err)
							return
						} else if err != nil && !errors.Is(err, io.EOF) {
							log.Error().Msgf("error when getting message: %s", err)
							return
						}
						if genericMessage == nil {
							return
						}
						switch message := genericMessage.(type) {
						case *ssh3Messages.ChannelRequestMessage:
							switch requestMessage := message.ChannelRequest.(type) {
							case *ssh3Messages.PtyRequest:
								err = newPtyReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.X11Request:
								err = newX11Req(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ShellRequest:
								err = newShellReq(authenticatedUser, channel, message.WantReply)
							case *ssh3Messages.ExecRequest:
								err = newCommandInShellReq(authenticatedUser, channel, message.WantReply, requestMessage.Command)
							case *ssh3Messages.SubsystemRequest:
								err = newSubsystemReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.WindowChangeRequest:
								err = newWindowChangeReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.SignalRequest:
								err = newSignalReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ExitStatusRequest:
								err = newExitStatusReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							case *ssh3Messages.ExitSignalRequest:
								err = newExitSignalReq(authenticatedUser, channel, *requestMessage, message.WantReply)
							}
						case *ssh3Messages.DataOrExtendedDataMessage:
							runningSession, ok := runningSessions.Get(channel)
							if ok && runningSession.channelState == LARVAL {
								if message.Data == string("forward-agent") {
									runningSession.authAgentSocketPath, err = openAgentSocketAndForwardAgent(conv.Context(), conv, authenticatedUser)
								} else {
									// invalid data on larval state
									err = fmt.Errorf("invalid data on ssh channel with LARVAL state")
								}
							} else {
								err = newDataReq(authenticatedUser, channel, *message)
							}
						}
						if err != nil {
							log.Error().Msgf("error while processing message: %+v: %+v\n", genericMessage, err)
							return
						}
					}
				}()
			}

		}
	})
	ssh3Handler := ssh3Server.GetHTTPHandlerFunc(context.Background())
	handler, err := server_auth.HandleAuths(context.Background(), enablePasswordLogin, 30000, ssh3Handler)
	if err != nil {
		log.Error().Msgf("Could not get authentication handlers: %s", err)
		return -1
	}
	mux.HandleFunc(*urlPath, handler)
	server.Handler = mux
	outputMessage := fmt.Sprintf("Server started, listening on %s%s", *bindAddr, *urlPath)
	fmt.Fprintln(os.Stderr, outputMessage)
	log.Info().Msg(outputMessage)
	err = server.ListenAndServe()

	if err != nil {
		log.Error().Msgf("error while serving HTTP connection: %s", err)
		return -1
	}

	return 0
}
