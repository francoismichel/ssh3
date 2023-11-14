package ssh3

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	util "ssh3/src/util"
)

var ChannelRequestParseFuncs = map[string]func(util.Reader) (ChannelRequest, error){
	"pty-req":       ParsePtyRequest,
	"x11-req":       ParseX11Request,
	"shell":         ParseShellRequest,
	"exec":          ParseExecRequest,
	"subsystem":     ParseSubsystemRequest,
	"window-change": ParseWindowChangeRequest,
	"signal":        ParseSignalRequest,
	"exit-status":   ParseExitStatusRequest,
	"exit-signal":   ParseExitSignalRequest,
}

type ChannelRequestMessage struct {
	WantReply bool
	ChannelRequest
}

var _ Message = &ChannelRequestMessage{}

func (m *ChannelRequestMessage) Length() (n int) {
	// msg type + request type + wantReply + request content
	return int(util.VarIntLen(SSH_MSG_CHANNEL_REQUEST)) + util.SSHStringLen(m.ChannelRequest.RequestTypeStr()) + 1 + m.ChannelRequest.Length()
}

func (m *ChannelRequestMessage) Write(buf []byte) (consumed int, err error) {
	if len(buf) < m.Length() {
		return 0, fmt.Errorf("buffer too small to write message for channel request of type %T: %d < %d", m.ChannelRequest, len(buf), m.Length())
	}

	msgTypeBuf := util.AppendVarInt(nil, uint64(SSH_MSG_CHANNEL_REQUEST))
	consumed += copy(buf[consumed:], msgTypeBuf)

	n, err := util.WriteSSHString(buf[consumed:], m.ChannelRequest.RequestTypeStr())
	if err != nil {
		return 0, err
	}
	consumed += n

	if m.WantReply {
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
func ParseRequestMessage(buf util.Reader) (*ChannelRequestMessage, error) {
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
	if !ok {
		return nil, fmt.Errorf("invalid request message type %s", requestType)
	}
	channelRequest, err := parseFunc(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &ChannelRequestMessage{
		WantReply:      wantReply,
		ChannelRequest: channelRequest,
	}, err
}

type ChannelRequest interface {
	Write(buf []byte) (n int, err error)
	Length() int
	RequestTypeStr() string
}

// see RFC4254 Sec 6.2
type PtyRequest struct {
	Term                 string
	CharWidth            uint64
	CharHeight           uint64
	PixelWidth           uint64
	PixelHeight          uint64
	EncodedTerminalModes string
}

var _ ChannelRequest = &PtyRequest{}

func ParsePtyRequest(buf util.Reader) (ChannelRequest, error) {
	term, err := util.ParseSSHString(buf)
	if err != nil {
		return nil, err
	}
	charWidth, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	charHeight, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	pixelWidth, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	pixelHeight, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	encodedTerminalModes, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &PtyRequest{
		Term:                 term,
		CharWidth:            charWidth,
		CharHeight:           charHeight,
		PixelWidth:           pixelWidth,
		PixelHeight:          pixelHeight,
		EncodedTerminalModes: encodedTerminalModes,
	}, err
}

func (r *PtyRequest) Length() int {
	return util.SSHStringLen(r.Term) +
		int(util.VarIntLen(r.CharWidth)) +
		int(util.VarIntLen(r.CharHeight)) +
		int(util.VarIntLen(r.PixelWidth)) +
		int(util.VarIntLen(r.PixelHeight)) +
		util.SSHStringLen(r.EncodedTerminalModes)
}

func (r *PtyRequest) RequestTypeStr() string {
	return "pty-req"
}

func (r *PtyRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}

	n, err := util.WriteSSHString(buf, r.Term)
	if err != nil {
		return 0, err
	}
	consumed += n

	var attrs []byte
	for _, attr := range []uint64{r.CharWidth, r.CharHeight, r.PixelWidth, r.PixelHeight} {
		attrs = util.AppendVarInt(attrs, attr)
	}
	consumed += copy(buf[consumed:], attrs)

	n, err = util.WriteSSHString(buf[consumed:], r.EncodedTerminalModes)
	if err != nil {
		return 0, err
	}
	consumed += n

	return consumed, nil
}

// see RFC4254 Sec 6.3.1
type X11Request struct {
	SingleConnection          bool
	X11AuthenticationProtocol string
	X11AuthenticationCookie   string
	X11ScreenNumber           uint64
}

var _ ChannelRequest = &X11Request{}

func ParseX11Request(buf util.Reader) (ChannelRequest, error) {
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
	x11ScreenNumber, err := util.ReadVarInt(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &X11Request{
		SingleConnection:          singleConnection,
		X11AuthenticationProtocol: x11AuthenticationProtocol,
		X11AuthenticationCookie:   x11AuthenticationCookie,
		X11ScreenNumber:           x11ScreenNumber,
	}, err
}

func (r *X11Request) Length() int {
	return 1 +
		int(util.SSHStringLen(r.X11AuthenticationProtocol)) +
		int(util.SSHStringLen(r.X11AuthenticationCookie)) +
		int(util.VarIntLen(r.X11ScreenNumber))
}

func (r *X11Request) RequestTypeStr() string {
	return "x11-req"
}

func (r *X11Request) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write X11 request")
	}

	if r.SingleConnection {
		buf[0] = 1
	} else {
		buf[0] = 0
	}
	consumed += 1

	n, err := util.WriteSSHString(buf[consumed:], r.X11AuthenticationProtocol)
	if err != nil {
		return 0, err
	}
	consumed += n

	n, err = util.WriteSSHString(buf[consumed:], r.X11AuthenticationCookie)
	if err != nil {
		return 0, err
	}
	consumed += n

	screenNumberBuf := util.AppendVarInt(nil, r.X11ScreenNumber)
	n = copy(buf[consumed:], screenNumberBuf)
	consumed += n

	return consumed, nil
}

type ShellRequest struct{}

var _ ChannelRequest = &ShellRequest{}

func ParseShellRequest(buf util.Reader) (ChannelRequest, error) {
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

type ExecRequest struct {
	Command string
}

var _ ChannelRequest = &ExecRequest{}

func ParseExecRequest(buf util.Reader) (ChannelRequest, error) {
	command, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &ExecRequest{
		Command: command,
	}, err
}

func (r *ExecRequest) Length() int {
	return util.SSHStringLen(r.Command)
}

func (r *ExecRequest) RequestTypeStr() string {
	return "exec"
}

func (r *ExecRequest) Write(buf []byte) (int, error) {
	return util.WriteSSHString(buf, r.Command)
}

type SubsystemRequest struct {
	SubsystemName string
}

var _ ChannelRequest = &SubsystemRequest{}

func ParseSubsystemRequest(buf util.Reader) (ChannelRequest, error) {
	subsystemName, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &SubsystemRequest{
		SubsystemName: subsystemName,
	}, err
}

func (r *SubsystemRequest) Length() int {
	return util.SSHStringLen(r.SubsystemName)
}

func (r *SubsystemRequest) RequestTypeStr() string {
	return "subsystem"
}

func (r *SubsystemRequest) Write(buf []byte) (int, error) {
	return util.WriteSSHString(buf, r.SubsystemName)
}

type WindowChangeRequest struct {
	CharWidth   uint64
	CharHeight  uint64
	PixelWidth  uint64
	PixelHeight uint64
}

var _ ChannelRequest = &WindowChangeRequest{}

func ParseWindowChangeRequest(buf util.Reader) (ChannelRequest, error) {
	charWidth, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	charHeight, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	pixelWidth, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}
	pixelHeight, err := util.ReadVarInt(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &WindowChangeRequest{
		CharWidth:   charWidth,
		CharHeight:  charHeight,
		PixelWidth:  pixelWidth,
		PixelHeight: pixelHeight,
	}, err
}

func (r *WindowChangeRequest) Length() int {
	return int(util.VarIntLen(r.CharWidth)) +
		int(util.VarIntLen(r.CharHeight)) +
		int(util.VarIntLen(r.PixelWidth)) +
		int(util.VarIntLen(r.PixelHeight))
}

func (r *WindowChangeRequest) RequestTypeStr() string {
	return "window-change"
}

func (r *WindowChangeRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}

	var attrs []byte
	for _, attr := range []uint64{r.CharWidth, r.CharHeight, r.PixelWidth, r.PixelHeight} {
		attrs = util.AppendVarInt(attrs, attr)
	}
	consumed += copy(buf[consumed:], attrs)

	return consumed, nil
}

type SignalRequest struct {
	SignalNameWithoutSig string
}

var _ ChannelRequest = &SignalRequest{}

func ParseSignalRequest(buf util.Reader) (ChannelRequest, error) {
	signalNameWithoutSig, err := util.ParseSSHString(buf)
	if err != nil && err != io.EOF {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &SignalRequest{
		SignalNameWithoutSig: signalNameWithoutSig,
	}, err
}

func (r *SignalRequest) Length() int {
	return util.SSHStringLen(r.SignalNameWithoutSig)
}

func (r *SignalRequest) RequestTypeStr() string {
	return "signal"
}

func (r *SignalRequest) Write(buf []byte) (int, error) {
	return util.WriteSSHString(buf, r.SignalNameWithoutSig)
}

type ExitStatusRequest struct {
	ExitStatus uint64
}

var _ ChannelRequest = &ExitStatusRequest{}

func ParseExitStatusRequest(buf util.Reader) (ChannelRequest, error) {
	exitStatus, err := util.ReadVarInt(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return &ExitStatusRequest{
		ExitStatus: exitStatus,
	}, err
}

func (r *ExitStatusRequest) Length() int {
	return int(util.VarIntLen(r.ExitStatus))
}

func (r *ExitStatusRequest) RequestTypeStr() string {
	return "exit-status"
}

func (r *ExitStatusRequest) Write(buf []byte) (int, error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}
	attrBuf := util.AppendVarInt(nil, r.ExitStatus)
	n := copy(buf, attrBuf)
	return n, nil
}

type ExitSignalRequest struct {
	SignalNameWithoutSig string
	CoreDumped           bool
	ErrorMessageUTF8     string
	LanguageTag          string
}

var _ ChannelRequest = &ExitSignalRequest{}

func ParseExitSignalRequest(buf util.Reader) (ChannelRequest, error) {
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
	if err != nil && err != io.EOF {
		return nil, bufio.ErrAdvanceTooFar
	}
	return &ExitSignalRequest{
		SignalNameWithoutSig: signalNameWithoutSig,
		CoreDumped:           coreDumped,
		ErrorMessageUTF8:     errorMessageUTF8,
		LanguageTag:          languageTag,
	}, err
}

func (r *ExitSignalRequest) Length() int {
	return util.SSHStringLen(r.SignalNameWithoutSig) +
		1 +
		util.SSHStringLen(r.ErrorMessageUTF8) +
		util.SSHStringLen(r.LanguageTag)
}

func (r *ExitSignalRequest) RequestTypeStr() string {
	return "exit-signal"
}

func (r *ExitSignalRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write PTY request")
	}
	n, err := util.WriteSSHString(buf[consumed:], r.SignalNameWithoutSig)
	if err != nil {
		return 0, err
	}
	consumed += n

	if r.CoreDumped {
		buf[consumed] = 1
	} else {
		buf[consumed] = 0
	}
	consumed += 1

	n, err = util.WriteSSHString(buf[consumed:], r.ErrorMessageUTF8)
	if err != nil {
		return 0, err
	}
	consumed += n

	n, err = util.WriteSSHString(buf[consumed:], r.LanguageTag)
	if err != nil {
		return 0, err
	}
	consumed += n

	return consumed, nil
}

type ForwardingRequest struct {
	Protocol      util.SSHForwardingProtocol
	AddressFamily util.SSHForwardingAddressFamily
	IpAddress     net.IP
	Port          uint16
}

var _ ChannelRequest = &ForwardingRequest{}

func ParseForwardingRequest(buf util.Reader) (ChannelRequest, error) {
	protocol, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}

	if protocol != util.SSHForwardingProtocolTCP && protocol != util.SSHProtocolUDP {
		return nil, fmt.Errorf("invalid protocol number: %d", protocol)
	}

	addressFamily, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, err
	}

	var address net.IP
	if addressFamily == util.SSHAFIpv4 {
		address = make([]byte, 4)
	} else if addressFamily == util.SSHAFIpv6 {
		address = make([]byte, 16)
	} else {
		return nil, fmt.Errorf("invalid address family: %d", addressFamily)
	}

	_, err = buf.Read(address)
	if err != nil {
		return nil, err
	}

	var portBuf [2]byte
	_, err = buf.Read(portBuf[:])
	if err != nil && err != io.EOF {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	return &ForwardingRequest{
		Protocol:      protocol,
		AddressFamily: addressFamily,
		IpAddress:     address,
		Port:          port,
	}, err
}

func (r *ForwardingRequest) Length() int {
	return int(util.VarIntLen(r.Protocol)) +
		int(util.VarIntLen(r.AddressFamily)) +
		len(r.IpAddress) +
		2
}

func (r *ForwardingRequest) RequestTypeStr() string {
	return "forward-port"
}

func (r *ForwardingRequest) Write(buf []byte) (consumed int, err error) {
	if len(buf) < r.Length() {
		return 0, errors.New("buffer too small to write forwarding request")
	}

	var attrs []byte
	for _, attr := range []uint64{r.AddressFamily, r.Protocol} {
		attrs = util.AppendVarInt(attrs, attr)
	}

	consumed += copy(buf[consumed:], attrs)
	consumed += copy(r.IpAddress, attrs)
	binary.BigEndian.PutUint16(buf[consumed:], r.Port)
	consumed += 2

	return consumed, nil
}

// XXX: MASQUE could (should?) be used instead of this handwritten implementation
