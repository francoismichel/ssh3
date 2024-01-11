package message

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand"

	"github.com/francoismichel/soh/util"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Messages", func() {
	const CHANNEL_OPEN_CONFIRMATION = 91
	const CHANNEL_OPEN_FAILURE = 92
	const CLASSICAL_DATA = 94
	const EXTENDED_DATA = 95
	const CHANNEL_REQUEST = 98
	const EXTENDED_DATA_TYPE = 10000000
	small_message_data := "hello, world!"
	empty_message_data := ""
	large_message_data := make([]byte, 5000000)

	var small_message, empty_message, large_message *DataOrExtendedDataMessage
	var small_binary_message, empty_binary_message, large_binary_message []byte
	var small_binary_extended_message, empty_binary_extended_message, large_binary_extended_message []byte

	BeforeEach(func() {
		_, err := rand.Read(large_message_data)
		Expect(err).To(BeNil())

		small_message = &DataOrExtendedDataMessage{
			DataType: 0,
			Data:     small_message_data,
		}
		empty_message = &DataOrExtendedDataMessage{
			DataType: 0,
			Data:     empty_message_data,
		}
		large_message = &DataOrExtendedDataMessage{
			DataType: 0,
			Data:     string(large_message_data),
		}

		small_binary_message = util.AppendVarInt(nil, CLASSICAL_DATA)
		small_binary_message = append(small_binary_message, util.AppendVarInt(nil, uint64(len(small_message_data)))...)
		small_binary_message = append(small_binary_message, []byte(small_message_data)...)

		empty_binary_message = util.AppendVarInt(nil, CLASSICAL_DATA)
		empty_binary_message = append(empty_binary_message, util.AppendVarInt(nil, uint64(len(empty_message_data)))...)
		empty_binary_message = append(empty_binary_message, []byte(empty_message_data)...)

		large_binary_message = util.AppendVarInt(nil, CLASSICAL_DATA)
		large_binary_message = append(large_binary_message, util.AppendVarInt(nil, uint64(len(large_message_data)))...)
		large_binary_message = append(large_binary_message, large_message_data...)

		small_binary_extended_message = util.AppendVarInt(nil, EXTENDED_DATA)
		small_binary_extended_message = append(small_binary_extended_message, util.AppendVarInt(nil, EXTENDED_DATA_TYPE)...)
		small_binary_extended_message = append(small_binary_extended_message, util.AppendVarInt(nil, uint64(len(small_message_data)))...)
		small_binary_extended_message = append(small_binary_extended_message, []byte(small_message_data)...)

		empty_binary_extended_message = util.AppendVarInt(nil, EXTENDED_DATA)
		empty_binary_extended_message = append(empty_binary_extended_message, util.AppendVarInt(nil, EXTENDED_DATA_TYPE)...)
		empty_binary_extended_message = append(empty_binary_extended_message, util.AppendVarInt(nil, uint64(len(empty_message_data)))...)
		empty_binary_extended_message = append(empty_binary_extended_message, []byte(empty_message_data)...)

		large_binary_extended_message = util.AppendVarInt(nil, EXTENDED_DATA)
		large_binary_extended_message = append(large_binary_extended_message, util.AppendVarInt(nil, EXTENDED_DATA_TYPE)...)
		large_binary_extended_message = append(large_binary_extended_message, util.AppendVarInt(nil, uint64(len(large_message_data)))...)
		large_binary_extended_message = append(large_binary_extended_message, []byte(large_message_data)...)

	})

	Context("Data messages", func() {
		Context("Parsing", func() {
			It("Should parse small data messages", func() {
				r := bytes.NewReader(small_binary_message)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(parsed_message).To(Equal(small_message))
			})

			It("Should parse empty data messages", func() {
				r := bytes.NewReader(empty_binary_message)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(parsed_message).To(Equal(empty_message))
			})

			It("Should parse large data messages", func() {
				r := bytes.NewReader(large_binary_message)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(parsed_message).To(Equal(large_message))
			})
		})

		Context("Writing", func() {
			It("Should write small data messages", func() {
				buf := make([]byte, small_message.Length())
				n, err := small_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(small_binary_message))
			})

			It("Should parse empty data messages", func() {
				buf := make([]byte, empty_message.Length())
				n, err := empty_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(empty_binary_message))
			})

			It("Should parse large data messages", func() {
				buf := make([]byte, large_message.Length())
				n, err := large_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(large_binary_message))
			})
		})
	})

	Context("ExtendedData messages", func() {
		Context("Parsing", func() {
			It("Should parse small data messages", func() {
				r := bytes.NewReader(small_binary_extended_message)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				small_message.DataType = EXTENDED_DATA_TYPE
				Expect(parsed_message).To(Equal(small_message))
			})

			It("Should parse empty data messages", func() {
				r := bytes.NewReader(empty_binary_extended_message)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				empty_message.DataType = EXTENDED_DATA_TYPE
				Expect(parsed_message).To(Equal(empty_message))
			})

			It("Should parse large data messages", func() {
				r := bytes.NewReader(large_binary_extended_message)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				large_message.DataType = EXTENDED_DATA_TYPE
				Expect(parsed_message).To(Equal(large_message))
			})
		})

		Context("Writing", func() {
			It("Should write small data messages", func() {
				small_message.DataType = EXTENDED_DATA_TYPE
				buf := make([]byte, small_message.Length())
				n, err := small_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(small_binary_extended_message))
			})

			It("Should parse empty data messages", func() {
				empty_message.DataType = EXTENDED_DATA_TYPE
				buf := make([]byte, empty_message.Length())
				n, err := empty_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(empty_binary_extended_message))
			})

			It("Should parse large data messages", func() {
				large_message.DataType = EXTENDED_DATA_TYPE
				buf := make([]byte, large_message.Length())
				n, err := large_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(large_binary_extended_message))
			})
		})
	})

	Context("Request messages", func() {
		generateSSHBool := func() (bool, byte) {
			wantReplyRandVal := byte(mathrand.Int())
			wantReply := wantReplyRandVal%2 == 0
			wantReplyByte := byte(0)
			if wantReply {
				// TOOD: handle ssh booleans larger than 1 (handling it in the tests would make the tests overcomplicated)
				wantReplyByte = 1
			}
			return wantReply, wantReplyByte
		}
		largeStringBytes := make([]byte, 1024)
		rand.Reader.Read(largeStringBytes)

		largeString := string(largeStringBytes)
		term := largeString[:100]
		wantReply, wantReplyByte := generateSSHBool()
		encodedModes := largeString[100:600]
		charWidth, charHeight, pixelWidth, pixelHeight := mathrand.Uint64()%(1<<60), mathrand.Uint64()%(1<<60), mathrand.Uint64()%(1<<60), mathrand.Uint64()%(1<<60)

		pty_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		pty_req_binary = util.AppendVarInt(pty_req_binary, uint64(len("pty-req")))
		pty_req_binary = append(pty_req_binary, "pty-req"...)
		pty_req_binary = append(pty_req_binary, wantReplyByte)
		pty_req_binary = util.AppendVarInt(pty_req_binary, uint64(len(term)))
		pty_req_binary = append(pty_req_binary, term...)
		pty_req_binary = util.AppendVarInt(pty_req_binary, charWidth)
		pty_req_binary = util.AppendVarInt(pty_req_binary, charHeight)
		pty_req_binary = util.AppendVarInt(pty_req_binary, pixelWidth)
		pty_req_binary = util.AppendVarInt(pty_req_binary, pixelHeight)
		pty_req_binary = util.AppendVarInt(pty_req_binary, uint64(len(encodedModes)))
		pty_req_binary = append(pty_req_binary, encodedModes...)

		pty_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &PtyRequest{
				Term:                 term,
				CharWidth:            charWidth,
				CharHeight:           charHeight,
				PixelWidth:           pixelWidth,
				PixelHeight:          pixelHeight,
				EncodedTerminalModes: encodedModes,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		singleConnection, singleConnectionByte := generateSSHBool()

		x11AuthenticationProtocol := largeString[:100]
		x11AuthenticationCookie := largeString[100:500]
		screenNumber := mathrand.Uint64() % (1 << 60)
		x11_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		x11_req_binary = util.AppendVarInt(x11_req_binary, uint64(len("x11-req")))
		x11_req_binary = append(x11_req_binary, "x11-req"...)
		x11_req_binary = append(x11_req_binary, wantReplyByte)
		x11_req_binary = append(x11_req_binary, singleConnectionByte)
		x11_req_binary = util.AppendVarInt(x11_req_binary, uint64(len(x11AuthenticationProtocol)))
		x11_req_binary = append(x11_req_binary, x11AuthenticationProtocol...)
		x11_req_binary = util.AppendVarInt(x11_req_binary, uint64(len(x11AuthenticationCookie)))
		x11_req_binary = append(x11_req_binary, x11AuthenticationCookie...)
		x11_req_binary = util.AppendVarInt(x11_req_binary, uint64(screenNumber))

		x11_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &X11Request{
				SingleConnection:          singleConnection,
				X11AuthenticationProtocol: x11AuthenticationProtocol,
				X11AuthenticationCookie:   x11AuthenticationCookie,
				X11ScreenNumber:           screenNumber,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		shell_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		shell_req_binary = util.AppendVarInt(shell_req_binary, uint64(len("shell")))
		shell_req_binary = append(shell_req_binary, "shell"...)
		shell_req_binary = append(shell_req_binary, wantReplyByte)

		shell_req_message := &ChannelRequestMessage{
			WantReply:      wantReply,
			ChannelRequest: &ShellRequest{},
		}

		wantReply, wantReplyByte = generateSSHBool()
		execCommand := largeString
		exec_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		exec_req_binary = util.AppendVarInt(exec_req_binary, uint64(len("exec")))
		exec_req_binary = append(exec_req_binary, "exec"...)
		exec_req_binary = append(exec_req_binary, wantReplyByte)
		exec_req_binary = util.AppendVarInt(exec_req_binary, uint64(len(execCommand)))
		exec_req_binary = append(exec_req_binary, execCommand...)

		exec_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &ExecRequest{
				Command: execCommand,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		subsystemName := largeString
		subsystem_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		subsystem_req_binary = util.AppendVarInt(subsystem_req_binary, uint64(len("subsystem")))
		subsystem_req_binary = append(subsystem_req_binary, "subsystem"...)
		subsystem_req_binary = append(subsystem_req_binary, wantReplyByte)
		subsystem_req_binary = util.AppendVarInt(subsystem_req_binary, uint64(len(subsystemName)))
		subsystem_req_binary = append(subsystem_req_binary, execCommand...)

		subsystem_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &SubsystemRequest{
				SubsystemName: subsystemName,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		window_change_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		window_change_req_binary = util.AppendVarInt(window_change_req_binary, uint64(len("window-change")))
		window_change_req_binary = append(window_change_req_binary, "window-change"...)
		window_change_req_binary = append(window_change_req_binary, wantReplyByte)
		window_change_req_binary = util.AppendVarInt(window_change_req_binary, charWidth)
		window_change_req_binary = util.AppendVarInt(window_change_req_binary, charHeight)
		window_change_req_binary = util.AppendVarInt(window_change_req_binary, pixelWidth)
		window_change_req_binary = util.AppendVarInt(window_change_req_binary, pixelHeight)

		window_change_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &WindowChangeRequest{
				CharWidth:   charWidth,
				CharHeight:  charHeight,
				PixelWidth:  pixelWidth,
				PixelHeight: pixelHeight,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		sigName := largeString
		signal_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		signal_req_binary = util.AppendVarInt(signal_req_binary, uint64(len("signal")))
		signal_req_binary = append(signal_req_binary, "signal"...)
		signal_req_binary = append(signal_req_binary, wantReplyByte)
		signal_req_binary = util.AppendVarInt(signal_req_binary, uint64(len(sigName)))
		signal_req_binary = append(signal_req_binary, sigName...)

		signal_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &SignalRequest{
				SignalNameWithoutSig: sigName,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		exitStatus := mathrand.Uint64() % (1 << 60)
		exit_status_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		exit_status_req_binary = util.AppendVarInt(exit_status_req_binary, uint64(len("exit-status")))
		exit_status_req_binary = append(exit_status_req_binary, "exit-status"...)
		exit_status_req_binary = append(exit_status_req_binary, wantReplyByte)
		exit_status_req_binary = util.AppendVarInt(exit_status_req_binary, exitStatus)

		exit_status_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &ExitStatusRequest{
				ExitStatus: exitStatus,
			},
		}

		wantReply, wantReplyByte = generateSSHBool()
		signalNameWithoutSig := largeString[:100]
		coreDumped, coreDumpedByte := generateSSHBool()
		errorMessageUTF8 := largeString[100:500]
		languageTag := largeString[500:700]
		exit_signal_req_binary := util.AppendVarInt(nil, CHANNEL_REQUEST)
		exit_signal_req_binary = util.AppendVarInt(exit_signal_req_binary, uint64(len("exit-signal")))
		exit_signal_req_binary = append(exit_signal_req_binary, "exit-signal"...)
		exit_signal_req_binary = append(exit_signal_req_binary, wantReplyByte)
		exit_signal_req_binary = util.AppendVarInt(exit_signal_req_binary, uint64(len(signalNameWithoutSig)))
		exit_signal_req_binary = append(exit_signal_req_binary, signalNameWithoutSig...)
		exit_signal_req_binary = append(exit_signal_req_binary, coreDumpedByte)
		exit_signal_req_binary = util.AppendVarInt(exit_signal_req_binary, uint64(len(errorMessageUTF8)))
		exit_signal_req_binary = append(exit_signal_req_binary, errorMessageUTF8...)
		exit_signal_req_binary = util.AppendVarInt(exit_signal_req_binary, uint64(len(languageTag)))
		exit_signal_req_binary = append(exit_signal_req_binary, languageTag...)

		exit_signal_req_message := &ChannelRequestMessage{
			WantReply: wantReply,
			ChannelRequest: &ExitSignalRequest{
				SignalNameWithoutSig: signalNameWithoutSig,
				CoreDumped:           coreDumped,
				ErrorMessageUTF8:     errorMessageUTF8,
				LanguageTag:          languageTag,
			},
		}

		Context("Parsing", func() {
			It("Parses a pty request", func() {
				r := bytes.NewReader(pty_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(pty_req_message))
			})

			It("Parses an x11 request", func() {
				r := bytes.NewReader(x11_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(x11_req_message))
			})

			It("Parses a shell request", func() {
				r := bytes.NewReader(shell_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(shell_req_message))
			})

			It("Parses an exec request", func() {
				r := bytes.NewReader(exec_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(exec_req_message))
			})

			It("Parses a subsystem request", func() {
				r := bytes.NewReader(subsystem_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(subsystem_req_message))
			})

			It("Parses a window change request", func() {
				r := bytes.NewReader(window_change_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(window_change_req_message))
			})

			It("Parses a signal request", func() {
				r := bytes.NewReader(signal_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(signal_req_message))
			})

			It("Parses an exit status request", func() {
				r := bytes.NewReader(exit_status_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(exit_status_req_message))
			})

			It("Parses an exit signal request", func() {
				r := bytes.NewReader(exit_signal_req_binary)
				msg, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(msg).To(Equal(exit_signal_req_message))
			})
		})

		Context("Writing", func() {
			It("Writes a pty request", func() {
				buf := make([]byte, pty_req_message.Length())
				n, err := pty_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(pty_req_binary))
			})

			It("Writes an x11 request", func() {
				buf := make([]byte, x11_req_message.Length())
				n, err := x11_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(x11_req_binary))
			})

			It("Writes a shell request", func() {
				buf := make([]byte, shell_req_message.Length())
				n, err := shell_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(shell_req_binary))
			})

			It("Writes an exec request", func() {
				buf := make([]byte, exec_req_message.Length())
				n, err := exec_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(exec_req_binary))
			})

			It("Writes a subsystem request", func() {
				buf := make([]byte, subsystem_req_message.Length())
				n, err := subsystem_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(subsystem_req_binary))
			})

			It("Writes a window change request", func() {
				buf := make([]byte, window_change_req_message.Length())
				n, err := window_change_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(window_change_req_binary))
			})

			It("Writes a signal request", func() {
				buf := make([]byte, signal_req_message.Length())
				n, err := signal_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(signal_req_binary))
			})

			It("Writes an exit status request", func() {
				buf := make([]byte, exit_status_req_message.Length())
				n, err := exit_status_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(exit_status_req_binary))
			})

			It("Writes an exit signal request", func() {
				buf := make([]byte, exit_signal_req_message.Length())
				n, err := exit_signal_req_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(exit_signal_req_binary))
			})

		})
	})

	Context("Channel open confirmation messages", func() {
		maxPacketSize := mathrand.Uint64() % (1 << 60)
		channel_open_confirmation_binary := util.AppendVarInt(nil, CHANNEL_OPEN_CONFIRMATION)
		channel_open_confirmation_binary = util.AppendVarInt(channel_open_confirmation_binary, maxPacketSize)

		channel_open_confirmation_message := &ChannelOpenConfirmationMessage{
			MaxPacketSize: maxPacketSize,
		}
		Context("Parsing", func() {
			It("Should parse a classical message", func() {
				r := bytes.NewReader(channel_open_confirmation_binary)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(parsed_message).To(Equal(channel_open_confirmation_message))
			})
		})

		Context("Writing", func() {
			It("Should write a classical message", func() {
				buf := make([]byte, channel_open_confirmation_message.Length())
				n, err := channel_open_confirmation_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(channel_open_confirmation_binary))
			})
		})
	})

	Context("Channel open failure messages", func() {
		largeStringBytes := make([]byte, 1024)
		rand.Reader.Read(largeStringBytes)

		largeString := string(largeStringBytes)
		errorString := largeString[:100]
		languageTag := largeString[100:200]
		reasonCode := mathrand.Uint64() % (1 << 60)
		channel_open_failure_binary := util.AppendVarInt(nil, CHANNEL_OPEN_FAILURE)
		channel_open_failure_binary = util.AppendVarInt(channel_open_failure_binary, reasonCode)
		channel_open_failure_binary = util.AppendVarInt(channel_open_failure_binary, uint64(len(errorString)))
		channel_open_failure_binary = append(channel_open_failure_binary, errorString...)
		channel_open_failure_binary = util.AppendVarInt(channel_open_failure_binary, uint64(len(languageTag)))
		channel_open_failure_binary = append(channel_open_failure_binary, languageTag...)

		channel_open_failure_message := &ChannelOpenFailureMessage{
			ReasonCode:       reasonCode,
			ErrorMessageUTF8: errorString,
			LanguageTag:      languageTag,
		}
		Context("Parsing", func() {
			It("Should parse a classical message", func() {
				r := bytes.NewReader(channel_open_failure_binary)
				parsed_message, err := ParseMessage(&util.BytesReadCloser{Reader: r})
				Expect(err).To(BeNil())
				Expect(parsed_message).To(Equal(channel_open_failure_message))
			})
		})

		Context("Writing", func() {
			It("Should write a classical message", func() {
				buf := make([]byte, channel_open_failure_message.Length())
				n, err := channel_open_failure_message.Write(buf)
				Expect(err).To(BeNil())
				Expect(n).To(BeEquivalentTo(len(buf)))
				Expect(buf).To(Equal(channel_open_failure_binary))
			})
		})
	})

})
