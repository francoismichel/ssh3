package ssh3

import (
	"fmt"
	"io"
	ssh3 "ssh3/src/message"
	"ssh3/src/util"
)

type ChannelOpenFailure struct{
	ReasonCode uint64
	ErrorMsg string
}
func (e ChannelOpenFailure) Error() string {
	return fmt.Sprintf("Channel open failure: reason: %d: %s", e.ReasonCode, e.ErrorMsg)
}

type MessageOnNonConfirmedChannel struct{
	message ssh3.Message
}
func (e MessageOnNonConfirmedChannel) Error() string {
	return fmt.Sprintf("A message of type %T has been received on a non-confirmed channel", e.message)
}


type PtyReqHandler func(channel *Channel, request ssh3.PtyRequest, wantReply bool)
type X11ReqHandler func(channel *Channel, request ssh3.X11Request, wantReply bool)
type ShellReqHandler func(channel *Channel, request ssh3.ShellRequest, wantReply bool)
type ExecReqHandler func(channel *Channel, request ssh3.ExecRequest, wantReply bool)
type SubsystemReqHandler func(channel *Channel, request ssh3.SubsystemRequest, wantReply bool)
type WindowChangeReqHandler func(channel *Channel, request ssh3.WindowChangeRequest, wantReply bool)
type SignalReqHandler func(channel *Channel, request ssh3.SignalRequest, wantReply bool)
type ExitStatusReqHandler func(channel *Channel, request ssh3.ExitStatusRequest, wantReply bool)
type ExitSignalReqHandler func(channel *Channel, request ssh3.ExitSignalRequest, wantReply bool)

type ChannelDataHandler func(channel *Channel, dataType ssh3.SSHDataType, data string)



type ChannelInfo struct {
	MaxPacketSize 		uint64
	ConversationID 		uint64
	ChannelID			uint64
	ChannelType 		string
}

type Channel struct {
	ChannelInfo
	confirmSent bool
	confirmReceived bool
	header []byte

	recv util.Reader
	send io.WriteCloser
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

func buildHeader(conversationID uint64, channelType string, maxPacketSize uint64) []byte {
	channelTypeBuf := make([]byte, util.SSHStringLen(channelType))
	util.WriteSSHString(channelTypeBuf, channelType)

	buf := util.AppendVarInt(nil, 0xaf3627e6)
	buf = util.AppendVarInt(buf, conversationID)
	buf = append(buf, channelTypeBuf...)
	buf = util.AppendVarInt(buf, maxPacketSize)
	return buf
}

func parseHeader(channelID uint64, r util.Reader) (*ChannelInfo, error) {
	conversationID, err := util.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	channelType, err := util.ParseSSHString(r)
	if err != nil {
		return nil, err
	}
	maxPacketSize, err := util.ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	return &ChannelInfo{
		ConversationID: conversationID,
		ChannelType: channelType,
		MaxPacketSize: maxPacketSize,
		ChannelID: channelID,
	}, nil
}

func NewChannel(conversationID uint64, channelID uint64, channelType string, maxPacketSize uint64, recv util.Reader, send io.WriteCloser, sendHeader bool, confirmSent bool, confirmReceived bool) *Channel {
	var header []byte = nil
	if sendHeader {
		header = buildHeader(conversationID, channelType, maxPacketSize)
	}
	return &Channel{
		ChannelInfo: ChannelInfo{
			MaxPacketSize: maxPacketSize,
			ConversationID: conversationID,
			ChannelID: channelID,
			ChannelType: channelType,
		},
		recv: recv,
		send: send,
		header: header,
		confirmSent: confirmSent,
		confirmReceived: confirmReceived,
	}
}

/// The error is EOF only if no bytes were read. If an EOF happens
/// after reading some but not all the bytes, nextMessage returns
/// ErrUnexpectedEOF.
func (c *Channel) nextMessage() (ssh3.Message, error) {
	return ssh3.ParseMessage(c.recv)
}


// The returned  message will neither be ChannelOpenConfirmationMessage nor ChannelOpenFailureMessage
// as this function handles it internally
func (c *Channel) NextMessage() (ssh3.Message, error) {
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
			return nil, ChannelOpenFailure{ ReasonCode: message.ReasonCode, ErrorMsg: message.ErrorMessageUTF8 }
	}

	// TODO: might be problematic if a peer already sends data along the channel opening 
	if !c.confirmSent {
		return nil, MessageOnNonConfirmedChannel{ message: genericMessage }
	}
	return genericMessage, nil
}


func (c *Channel) maybeSendHeader() error {
	if len(c.header) > 0 {
		written, err := c.send.Write(c.header)
		if err != nil {
			return err
		}
		c.header = c.header[written:]
	}
	return nil
}

func (c *Channel) WriteData(dataBuf []byte, dataType ssh3.SSHDataType) (int, error) {
	err := c.maybeSendHeader()
	if err != nil {
		return 0, err
	}
	written := 0
	for len(dataBuf) > 0 {
		dataMsg := &ssh3.DataOrExtendedDataMessage{
			DataType: dataType,
			Data: "",
		}
		emptyMsgLen := dataMsg.Length()
		msgLen := util.MinUint64(c.ChannelInfo.MaxPacketSize - uint64(emptyMsgLen), uint64(len(dataBuf)))
	
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

func (c *Channel) confirmChannel(maxPacketSize uint64) error {
	err := c.sendMessage(&ssh3.ChannelOpenConfirmationMessage{MaxPacketSize: maxPacketSize})
	if err == nil {
		c.confirmSent = true
	}
	return err
}

func (c *Channel) sendMessage(m ssh3.Message) error {
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

func (c *Channel) SendRequest(r *ssh3.ChannelRequestMessage) error {
	//TODO: make it thread safe
	return c.sendMessage(r)
}

func (c *Channel) Close() {
	c.recv.Close()
}