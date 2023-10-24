package ssh3

import "io"

type ChannelInfo struct {
	MaxPacketSize 		uint64
	ConversationID 		uint64
}

type Channel struct {
	ChannelInfo
	recv io.Reader
	send io.Writer
}

func (c *Channel) SendMessage()