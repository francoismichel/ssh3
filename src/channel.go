package ssh3

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	ssh3 "ssh3/src/message"
	"ssh3/src/util"

	"github.com/quic-go/quic-go"
)

type ChannelOpenFailure struct {
	ReasonCode uint64
	ErrorMsg   string
}

func (e ChannelOpenFailure) Error() string {
	return fmt.Sprintf("Channel open failure: reason: %d: %s", e.ReasonCode, e.ErrorMsg)
}

type MessageOnNonConfirmedChannel struct {
	message ssh3.Message
}

func (e MessageOnNonConfirmedChannel) Error() string {
	return fmt.Sprintf("A message of type %T has been received on a non-confirmed channel", e.message)
}

type ReceivedDatagramOnNonDatagramChannel struct {
	channelID uint64
}

func (e ReceivedDatagramOnNonDatagramChannel) Error() string {
	return fmt.Sprintf("a datagram has been received on non-datagram channel %d", e.channelID)
}

type SentDatagramOnNonDatagramChannel struct {
	channelID uint64
}

func (e SentDatagramOnNonDatagramChannel) Error() string {
	return fmt.Sprintf("a datagram has been sent on non-datagram channel %d", e.channelID)
}

type PtyReqHandler func(channel Channel, request ssh3.PtyRequest, wantReply bool)
type X11ReqHandler func(channel Channel, request ssh3.X11Request, wantReply bool)
type ShellReqHandler func(channel Channel, request ssh3.ShellRequest, wantReply bool)
type ExecReqHandler func(channel Channel, request ssh3.ExecRequest, wantReply bool)
type SubsystemReqHandler func(channel Channel, request ssh3.SubsystemRequest, wantReply bool)
type WindowChangeReqHandler func(channel Channel, request ssh3.WindowChangeRequest, wantReply bool)
type SignalReqHandler func(channel Channel, request ssh3.SignalRequest, wantReply bool)
type ExitStatusReqHandler func(channel Channel, request ssh3.ExitStatusRequest, wantReply bool)
type ExitSignalReqHandler func(channel Channel, request ssh3.ExitSignalRequest, wantReply bool)

type ChannelDataHandler func(channel Channel, dataType ssh3.SSHDataType, data string)

type channelCloseListener interface {
	onChannelClose(channel Channel)
}

type ChannelInfo struct {
	MaxPacketSize  uint64
	ConversationStreamID uint64 
	ConversationID ConversationID 
	ChannelID      uint64
	ChannelType    string
}

type Channel interface {
	ChannelID() util.ChannelID
	ConversationID() ConversationID
	ConversationStreamID() uint64
	NextMessage() (ssh3.Message, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(datagram []byte) error
	SendRequest(r *ssh3.ChannelRequestMessage) error
	CancelRead()
	Close()
	MaxPacketSize() uint64
	WriteData(dataBuf []byte, dataType ssh3.SSHDataType) (int, error)
	ChannelType() string
	confirmChannel(maxPacketSize uint64) error
	setDatagramSender(func(datagram []byte) error)
	waitAddDatagram(ctx context.Context, datagram []byte) error
	addDatagram(datagram []byte) bool
	maybeSendHeader() error
	setDgramQueue(*util.DatagramsQueue)
}

type channelImpl struct {
	ChannelInfo
	confirmSent     bool
	confirmReceived bool
	header          []byte

	datagramSender util.SSH3DatagramSenderFunc

	channelCloseListener

	recv           quic.ReceiveStream
	send           io.WriteCloser
	datagramsQueue *util.DatagramsQueue
	PtyReqHandler
	X11ReqHandler
	ShellReqHandler
	ExecReqHandler
	SubsystemReqHandler
	WindowChangeReqHandler
	SignalReqHandler
	ExitStatusReqHandler
	ExitSignalReqHandler

	ChannelDataHandler
}

type UDPForwardingChannelImpl struct {
	RemoteAddr *net.UDPAddr
	Channel
}

type TCPForwardingChannelImpl struct {
	RemoteAddr *net.TCPAddr
	Channel
}

func buildHeader(conversationStreamID uint64, channelType string, maxPacketSize uint64, additionalBytes []byte) []byte {
	channelTypeBuf := make([]byte, util.SSHStringLen(channelType))
	util.WriteSSHString(channelTypeBuf, channelType)

	buf := util.AppendVarInt(nil, 0xaf3627e6)
	buf = util.AppendVarInt(buf, conversationStreamID)
	buf = append(buf, channelTypeBuf...)
	buf = util.AppendVarInt(buf, maxPacketSize)
	if additionalBytes != nil {
		buf = append(buf, additionalBytes...)
	}
	return buf
}

func buildForwardingChannelAdditionalBytes(remoteAddr net.IP, port uint16) []byte {
	var buf []byte

	var addressFamily util.SSHForwardingAddressFamily
	if len(remoteAddr) == 4 {
		addressFamily = util.SSHAFIpv4
	} else {
		addressFamily = util.SSHAFIpv6
	}

	buf = util.AppendVarInt(buf, addressFamily)

	buf = append(buf, remoteAddr...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	buf = append(buf, portBuf[:]...)
	return buf
}

func parseHeader(channelID uint64, r util.Reader) (conversationControlStreamID ControlStreamID, channelType string, maxPacketSize uint64, err error) {
	conversationControlStreamID, err = util.ReadVarInt(r)
	if err != nil {
		return 0, "", 0, err
	}
	channelType, err = util.ParseSSHString(r)
	if err != nil {
		return 0, "", 0, err
	}
	maxPacketSize, err = util.ReadVarInt(r)
	if err != nil {
		return 0, "", 0, err
	}
	return conversationControlStreamID, channelType, maxPacketSize, nil
}

func parseForwardingHeader(channelID uint64, buf util.Reader) (net.IP, uint16, error) {
	addressFamily, err := util.ReadVarInt(buf)
	if err != nil {
		return nil, 0, err
	}

	var address net.IP
	if addressFamily == util.SSHAFIpv4 {
		address = make([]byte, 4)
	} else if addressFamily == util.SSHAFIpv6 {
		address = make([]byte, 16)
	} else {
		return nil, 0, fmt.Errorf("invalid address family: %d", addressFamily)
	}

	_, err = buf.Read(address)
	if err != nil {
		return nil, 0, err
	}

	var portBuf [2]byte
	_, err = buf.Read(portBuf[:])
	if err != nil {
		return nil, 0, err
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	return address, port, nil
}

func parseUDPForwardingHeader(channelID uint64, buf util.Reader) (*net.UDPAddr, error) {
	address, port, err := parseForwardingHeader(channelID, buf)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{
		IP: address,
		Port: int(port),
	}, nil
}

func parseTCPForwardingHeader(channelID uint64, buf util.Reader) (*net.TCPAddr, error) {
	address, port, err := parseForwardingHeader(channelID, buf)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{
		IP: address,
		Port: int(port),
	}, nil
}

func NewChannel(conversationStreamID uint64, conversationID ConversationID, channelID uint64, channelType string, maxPacketSize uint64, recv quic.ReceiveStream,
	send io.WriteCloser, datagramSender util.SSH3DatagramSenderFunc, channelCloseListener channelCloseListener, sendHeader bool, confirmSent bool,
	confirmReceived bool, datagramsQueueSize uint64, additonalHeaderBytes []byte) Channel {
	var header []byte = nil
	if sendHeader {
		header = buildHeader(conversationStreamID, channelType, maxPacketSize, additonalHeaderBytes)
	}
	return &channelImpl{
		ChannelInfo: ChannelInfo{
			MaxPacketSize:  maxPacketSize,
			ConversationStreamID: conversationStreamID,
			ConversationID: conversationID,
			ChannelID:      channelID,
			ChannelType:    channelType,
		},
		recv:                 recv,
		send:                 send,
		datagramsQueue:       util.NewDatagramsQueue(datagramsQueueSize),
		datagramSender:       datagramSender,
		channelCloseListener: channelCloseListener,
		header:               header,
		confirmSent:          confirmSent,
		confirmReceived:      confirmReceived,
	}
}

func (c *channelImpl) ChannelID() util.ChannelID {
	return c.ChannelInfo.ChannelID
}

func (c *channelImpl) ConversationStreamID() uint64 {
	return c.ChannelInfo.ConversationStreamID
}

func (c *channelImpl) ConversationID() ConversationID {
	return c.ChannelInfo.ConversationID
}

// / The error is EOF only if no bytes were read. If an EOF happens
// / after reading some but not all the bytes, nextMessage returns
// / ErrUnexpectedEOF.
func (c *channelImpl) nextMessage() (ssh3.Message, error) {
	return ssh3.ParseMessage(util.NewReader(c.recv))
}

// The returned  message will neither be ChannelOpenConfirmationMessage nor ChannelOpenFailureMessage
// as this function handles it internally
func (c *channelImpl) NextMessage() (ssh3.Message, error) {
	genericMessage, err := c.nextMessage()
	if err != nil {
		return nil, err
	}

	switch message := genericMessage.(type) {
	case *ssh3.ChannelOpenConfirmationMessage:
		c.confirmReceived = true
		// let's read the next message
		return c.NextMessage()
	case *ssh3.ChannelOpenFailureMessage:
		return nil, ChannelOpenFailure{ReasonCode: message.ReasonCode, ErrorMsg: message.ErrorMessageUTF8}
	}

	// TODO: might be problematic if a peer already sends data along the channel opening
	if !c.confirmSent {
		return nil, MessageOnNonConfirmedChannel{message: genericMessage}
	}
	return genericMessage, nil
}

func (c *channelImpl) maybeSendHeader() error {
	if len(c.header) > 0 {
		written, err := c.send.Write(c.header)
		if err != nil {
			return err
		}
		c.header = c.header[written:]
	}
	return nil
}

func (c *channelImpl) WriteData(dataBuf []byte, dataType ssh3.SSHDataType) (int, error) {
	err := c.maybeSendHeader()
	if err != nil {
		return 0, err
	}
	written := 0
	for len(dataBuf) > 0 {
		dataMsg := &ssh3.DataOrExtendedDataMessage{
			DataType: dataType,
			Data:     "",
		}
		emptyMsgLen := dataMsg.Length()
		msgLen := util.MinUint64(c.ChannelInfo.MaxPacketSize-uint64(emptyMsgLen), uint64(len(dataBuf)))

		dataMsg.Data = string(dataBuf[:msgLen])
		dataBuf = dataBuf[msgLen:]
		// TODO: avoid unnecessary copies and buffer creations
		msgBuf := make([]byte, dataMsg.Length())
		_, err := dataMsg.Write(msgBuf)
		if err != nil {
			return written, err
		}
		n, err := c.send.Write(msgBuf)
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *channelImpl) confirmChannel(maxPacketSize uint64) error {
	err := c.sendMessage(&ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: maxPacketSize})
	if err == nil {
		c.confirmSent = true
	}
	return err
}

func (c *channelImpl) sendMessage(m ssh3.Message) error {
	err := c.maybeSendHeader()
	if err != nil {
		return err
	}
	buf := make([]byte, m.Length())
	_, err = m.Write(buf)
	if err != nil {
		return err
	}
	c.send.Write(buf)
	return nil
}

// blocks until the datagram is added
func (c *channelImpl) waitAddDatagram(ctx context.Context, datagram []byte) error {
	return c.datagramsQueue.WaitAdd(ctx, datagram)
}

// blocks until the datagram is added
func (c *channelImpl) addDatagram(datagram []byte) bool {
	return c.datagramsQueue.Add(datagram)
}

func (c *channelImpl) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.datagramsQueue.WaitNext(ctx)
}

func (c *channelImpl) SendDatagram(datagram []byte) error {
	c.maybeSendHeader()
	if c.datagramSender == nil {
		return SentDatagramOnNonDatagramChannel{c.ChannelID()}
	}
	return c.datagramSender(datagram)
}

func (c *channelImpl) SendRequest(r *ssh3.ChannelRequestMessage) error {
	//TODO: make it thread safe
	return c.sendMessage(r)
}

func (c *channelImpl) CancelRead() {
	c.recv.CancelRead(42)
}

func (c *channelImpl) Close() {
	c.send.Close()
}

func (c *channelImpl) MaxPacketSize() uint64 {
	return c.ChannelInfo.MaxPacketSize
}

func (c *channelImpl) ChannelType() string {
	return c.ChannelInfo.ChannelType
}

func (c *channelImpl) setDatagramSender(datagramSender func(datagram []byte) error) {
	c.datagramSender = datagramSender
}

func (c *channelImpl) setDgramQueue(q *util.DatagramsQueue) {
	c.datagramsQueue = q
}