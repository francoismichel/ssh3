package ssh3

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	util "ssh3/src/util"
)

var ChannelRequestParseFuncs = map[string]func (io.Reader) (ChannelRequest, error){
	"pty-req": ParsePtyRequest,
	"x11-req": ParseX11Request,
	"shell": ParseShellRequest,
	"exec": ParseExecRequest,
	"subsystem": ParseSubsystemRequest,
	"window-change": ParseWindowChangeRequest,
	"signal": ParseSignalRequest,
}

type ChannelRequestMessage struct {
	wantReply bool
	ChannelRequest
}

var _ Message = &ChannelRequestMessage{}

func (m *ChannelRequestMessage) Length() (n int) {
	// msg type + request type + wantReply + request content
	return 1 + util.SSHStringLen(m.ChannelRequest.RequestTypeStr()) + 1 + m.ChannelRequest.Length()
}

func (m *ChannelRequestMessage) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, fmt.Errorf("buffer too small to write message for channel request of type %T: %d < %d", m.ChannelRequest, len(buf), m.Length())
	}

	buf[0] = SSH_MSG_CHANNEL_REQUEST
	consumed += 1

	n, err := util.WriteSSHString(buf[consumed:], m.ChannelRequest.RequestTypeStr())
	if err != nil {
		return 0, err
	}
	consumed += n

	if m.wantReply {
		buf[consumed] = 1
	} else {
		buf[consumed] = 0
	}
	consumed += 1

	n, err = m.ChannelRequest.Write(buf[consumed:])
	if err != nil {
		return 0, err
	}
	consumed += n

	return consumed, nil
}

// The buffer points to the request-type attribute
func ParseRequestMessage(buf io.Reader) (*ChannelRequestMessage, error) {
	requestType, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	wantReply := false
	err = binary.Read(buf, binary.BigEndian, &wantReply)
	if err != nil {
		return nil, err
	}
	parseFunc, ok := ChannelRequestParseFuncs[requestType]
	if !ok{
		return nil, fmt.Errorf("invalid request message type %s", requestType)
	}
	channelRequest, err := parseFunc(buf)
	if err != nil {
		return nil, err
	}
	return &ChannelRequestMessage{
		wantReply: wantReply,
		ChannelRequest: channelRequest,
	}, nil
}

type ChannelRequest interface {
	Write(buf []byte) (n int, err error)
	Length() int
	RequestTypeStr() string
}

// see RFC4254 Sec 6.2
type PtyRequest struct {
	term string
	charWidth uint64
	charHeight uint64
	pixelWidth uint64
	pixelHeight uint64
	encodedTerminalModes string
}

var _ ChannelRequest = &PtyRequest{}

func ParsePtyRequest(buf io.Reader) (ChannelRequest, error) {
	term, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	byteReader := bufio.NewReader(buf)
	charWidth, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	charHeight, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	pixelWidth, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	pixelHeight, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	encodedTerminalModes, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	return &PtyRequest{
		term: term,
		charWidth: charWidth,
		charHeight: charHeight,
		pixelWidth: pixelWidth,
		pixelHeight: pixelHeight,
		encodedTerminalModes: encodedTerminalModes,
	}, nil
}

func (r *PtyRequest) Length() int {
	return util.SSHStringLen(r.term) +
			int(util.VarIntLen(r.charWidth)) +
			int(util.VarIntLen(r.charHeight)) +
			int(util.VarIntLen(r.pixelWidth)) +
			int(util.VarIntLen(r.pixelHeight)) +
			util.SSHStringLen(r.encodedTerminalModes)
}

func (r *PtyRequest) RequestTypeStr() string {
	return "pty-req"
}

func (r *PtyRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}

	n, err := util.WriteSSHString(buf, r.term)
	if err != nil {
		return 0, err
	}
	consumed += n

	var attrs []byte
	for _, attr := range []uint64{r.charWidth, r.charHeight, r.pixelWidth, r.pixelHeight} {
		util.AppendVarInt(attrs, attr)
	}
	consumed += copy(buf[consumed:], attrs)

	n, err = util.WriteSSHString(buf[consumed:], r.encodedTerminalModes)
	if err != nil {
		return 0, err
	}
	consumed += n

	return consumed, nil
}

// see RFC4254 Sec 6.3.1
type X11Request struct {
	singleConnection bool
	x11AuthenticationProtocol string
	x11AuthenticationCookie string
	x11ScreenNumber uint64
}

var _ ChannelRequest = &X11Request{}

func ParseX11Request(buf io.Reader) (ChannelRequest, error) {
	singleConnection := false
	err := binary.Read(buf, binary.BigEndian, &singleConnection)
	if err != nil {
		return nil, err
	}
	x11AuthenticationProtocol, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	x11AuthenticationCookie, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	byteReader := bufio.NewReader(buf)
	x11ScreenNumber, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	return &X11Request{
		singleConnection: singleConnection,
		x11AuthenticationProtocol: x11AuthenticationProtocol,
		x11AuthenticationCookie: x11AuthenticationCookie,
		x11ScreenNumber: x11ScreenNumber,
	}, nil
}

func (r *X11Request) Length() int {
	return  1 +
			int(util.SSHStringLen(r.x11AuthenticationProtocol)) +
			int(util.SSHStringLen(r.x11AuthenticationCookie)) +
			int(util.VarIntLen(r.x11ScreenNumber))
}

func (r *X11Request) RequestTypeStr() string {
	return "x11-req"
}

func (r *X11Request) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write X11 request")
	}
	
	if r.singleConnection {
		buf[0] = 1
	} else {
		buf[0] = 0
	}
	consumed += 1

	n, err := util.WriteSSHString(buf[consumed:], r.x11AuthenticationProtocol)
	if err != nil {
		return 0, err
	}
	consumed += n

	n, err = util.WriteSSHString(buf[consumed:], r.x11AuthenticationCookie)
	if err != nil {
		return 0, err
	}
	consumed += n

	screenNumberBuf := util.AppendVarInt(nil, r.x11ScreenNumber)
	n = copy(buf[consumed:], screenNumberBuf)
	consumed += n
	
	return consumed, nil
}

type ShellRequest struct{}

var _ ChannelRequest = &ShellRequest{}

func ParseShellRequest(buf io.Reader) (ChannelRequest, error) {
	return &ShellRequest{}, nil
}

func (r *ShellRequest) Length() int {
	return 0
}

func (r *ShellRequest) RequestTypeStr() string {
	return "shell"
}

func (r *ShellRequest) Write(buf []byte) (int, error) {
	return 0, nil
}


type ExecRequest struct{
	command string
}

var _ ChannelRequest = &ExecRequest{}

func ParseExecRequest(buf io.Reader) (ChannelRequest, error) {
	command, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &ExecRequest{
		command: command,
	}, nil
}

func (r *ExecRequest) Length() int {
	return util.SSHStringLen(r.command)
}

func (r *ExecRequest) RequestTypeStr() string {
	return "exec"
}

func (r *ExecRequest) Write(buf []byte) (int, error) {
	return util.WriteSSHString(buf, r.command)
}

type SubsystemRequest struct {
	subsystemName string
}

var _ ChannelRequest = &SubsystemRequest{}

func ParseSubsystemRequest(buf io.Reader) (ChannelRequest, error) {
	subsystemName, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &SubsystemRequest{
		subsystemName: subsystemName,
	}, nil
}

func (r *SubsystemRequest) Length() int {
	return util.SSHStringLen(r.subsystemName)
}

func (r *SubsystemRequest) RequestTypeStr() string {
	return "subsystem"
}

func (r *SubsystemRequest) Write(buf []byte) (int, error) {
	return util.WriteSSHString(buf, r.subsystemName)
}


type WindowChangeRequest struct {
	charWidth uint64
	charHeight uint64
	pixelWidth uint64
	pixelHeight uint64
}

var _ ChannelRequest = &WindowChangeRequest{}

func ParseWindowChangeRequest(buf io.Reader) (ChannelRequest, error) {
	byteReader := bufio.NewReader(buf)
	charWidth, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	charHeight, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	pixelWidth, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	pixelHeight, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	return &WindowChangeRequest{
		charWidth: charWidth,
		charHeight: charHeight,
		pixelWidth: pixelWidth,
		pixelHeight: pixelHeight,
	}, nil
}

func (r *WindowChangeRequest) Length() int {
	return int(util.VarIntLen(r.charWidth)) +
			int(util.VarIntLen(r.charHeight)) +
			int(util.VarIntLen(r.pixelWidth)) +
			int(util.VarIntLen(r.pixelHeight))
}

func (r *WindowChangeRequest) RequestTypeStr() string {
	return "window-change"
}

func (r *WindowChangeRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}

	var attrs []byte
	for _, attr := range []uint64{r.charWidth, r.charHeight, r.pixelWidth, r.pixelHeight} {
		util.AppendVarInt(attrs, attr)
	}
	consumed += copy(buf[consumed:], attrs)

	return consumed, nil
}


type SignalRequest struct {
	signalNameWithoutSig string
}

var _ ChannelRequest = &SignalRequest{}

func ParseSignalRequest(buf io.Reader) (ChannelRequest, error) {
	signalNameWithoutSig, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &SignalRequest{
		signalNameWithoutSig: signalNameWithoutSig,
	}, nil
}

func (r *SignalRequest) Length() int {
	return util.SSHStringLen(r.signalNameWithoutSig)
}

func (r *SignalRequest) RequestTypeStr() string {
	return "signal"
}

func (r *SignalRequest) Write(buf []byte) (int, error) {
	return util.WriteSSHString(buf, r.signalNameWithoutSig)
}

type ExitStatusRequest struct {
	exitStatus uint64
}

var _ ChannelRequest = &ExitStatusRequest{}

func ParseExitStatusRequest(buf io.Reader) (ChannelRequest, error) {
	byteReader := bufio.NewReader(buf)
	exitStatus, err := util.ReadVarInt(byteReader)
	if err != nil {
		return nil, err
	}
	return &ExitStatusRequest{
		exitStatus: exitStatus,
	}, nil
}

func (r *ExitStatusRequest) Length() int {
	return int(util.VarIntLen(r.exitStatus))
}

func (r *ExitStatusRequest) RequestTypeStr() string {
	return "signal"
}

func (r *ExitStatusRequest) Write(buf []byte) (int, error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}
	attrBuf := util.AppendVarInt(nil, r.exitStatus)
	n := copy(buf, attrBuf)
	return n, nil
}


type ExitSignalRequest struct {
	signalNameWithoutSig string
	coreDumped bool
	errorMessageUTF8 string
	languageTag string
}

var _ ChannelRequest = &ExitSignalRequest{}

func ParseExitSignalRequest(buf io.Reader) (ChannelRequest, error) {
	signalNameWithoutSig, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, bufio.ErrAdvanceTooFar
	}
	coreDumped := false
	err = binary.Read(buf, binary.BigEndian, &coreDumped)
	if err != nil {
		return nil, err
	}

	errorMessageUTF8, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, bufio.ErrAdvanceTooFar
	}

	languageTag, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &ExitSignalRequest{
		signalNameWithoutSig: signalNameWithoutSig,
		coreDumped: coreDumped,
		errorMessageUTF8: errorMessageUTF8,
		languageTag: languageTag,
	}, nil
}

func (r *ExitSignalRequest) Length() int {
	return util.SSHStringLen(r.signalNameWithoutSig) +
		   1 +
		   util.SSHStringLen(r.errorMessageUTF8) +
		   util.SSHStringLen(r.languageTag)
}

func (r *ExitSignalRequest) RequestTypeStr() string {
	return "exit-signal"
}

func (r *ExitSignalRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}
	n, err := util.WriteSSHString(buf, r.signalNameWithoutSig)
	if err != nil {
		return 0, err
	}
	consumed += n

	if r.coreDumped {
		buf[consumed] = 1
	} else {
		buf[consumed] = 0
	}
	consumed += 1


	n, err = util.WriteSSHString(buf, r.errorMessageUTF8)
	if err != nil {
		return 0, err
	}
	consumed += n

	n, err = util.WriteSSHString(buf, r.languageTag)
	if err != nil {
		return 0, err
	}
	consumed += n

	return consumed, nil
}

// XXX: port forwarding is not implemented on purpose, MASQUE could be used instead