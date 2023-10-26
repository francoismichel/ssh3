package ssh3

import (
	"io"
	ssh3 "ssh3/src/message"
	"ssh3/src/util"
)

type PtyReqHandler func(channel *Channel, request ssh3.PtyRequest, wantReply bool) bool
type X11ReqHandler func(channel *Channel, request ssh3.X11Request, wantReply bool) bool
type ShellReqHandler func(channel *Channel, request ssh3.ShellRequest, wantReply bool) bool
type ExecReqHandler func(channel *Channel, request ssh3.ExecRequest, wantReply bool) bool
type SubsystemReqHandler func(channel *Channel, request ssh3.SubsystemRequest, wantReply bool) bool
type WindowChangeReqHandler func(channel *Channel, request ssh3.WindowChangeRequest, wantReply bool) bool
type SignalReqHandler func(channel *Channel, request ssh3.SignalRequest, wantReply bool) bool
type ExitStatusReqHandler func(channel *Channel, request ssh3.ExitStatusRequest, wantReply bool) bool
type ExitSignalReqHandler func(channel *Channel, request ssh3.ExitSignalRequest, wantReply bool) bool

type ChannelDataHandler func(channel *Channel, dataType ssh3.SSHDataType, data string)

type ChannelInfo struct {
	MaxPacketSize 		uint64
	ConversationID 		uint64
}

type Channel struct {
	ChannelInfo
	recv util.Reader
	send io.Writer
	maxPacketSize uint64
	dataBuf []byte
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

/// The error is EOF only if no bytes were read. If an EOF happens
/// after reading some but not all the bytes, nextMessage returns
/// ErrUnexpectedEOF.
func (c *Channel) nextMessage() (ssh3.Message, error) {
	return ssh3.ParseMessage(c.recv)
}

func (c *Channel) getAndHandleNextMessage() error {
	genericMessage, err := c.nextMessage()
	if err != nil {
		return nil
	}
	switch message := genericMessage.(type) {
		case *ssh3.ChannelRequestMessage:
			switch requestMessage := message.ChannelRequest.(type) {
				case *ssh3.PtyRequest:
					c.PtyReqHandler(c, *requestMessage, message.WantReply)
			}
		case *ssh3.DataOrExtendedDataMessage:
			c.ChannelDataHandler(c, message.DataType, message.Data)
	}
	return nil
}

func (c *Channel) flushOneDataMsg(dataType ssh3.SSHDataType) error {
	if len(c.dataBuf) > 0 {
		dataMsg := &ssh3.DataOrExtendedDataMessage{
			DataType: dataType,
			Data: "",
		}
		emptyMsgLen := dataMsg.Length()
		msgLen := util.MinUint64(c.maxPacketSize - uint64(emptyMsgLen), uint64(len(c.dataBuf)))

		dataMsg.Data = string(c.dataBuf[:msgLen])
		c.dataBuf = c.dataBuf[msgLen:]

		buf := make([]byte, dataMsg.Length())
		dataMsg.Write(buf)

		sent := 0
		for sent != len(buf) {
			n, err := c.send.Write(buf[sent:])
			if err != nil {
				return err
			}
			sent += n
		}
	}

	return nil
}


func (c *Channel) SendMessage() {}