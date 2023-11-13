package ssh3

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"ssh3/src/util"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const SSH_FRAME_TYPE = 0xaf3627e6

type Conversation struct {
	controlStream   http3.Stream
	maxPacketSize   uint64
	streamCreator   http3.StreamCreator
	datagramSender  util.DatagramSender
	channelsManager *channelsManager

	channelsAcceptQueue *util.AcceptQueue[Channel]
}

func EstablishNewClientConversation(req *http.Request, roundTripper *http3.RoundTripper, maxPacketsize uint64, defaultDatagramsQueueSize uint64) (*Conversation, error) {
	conv := &Conversation{
		controlStream:       nil,
		channelsAcceptQueue: util.NewAcceptQueue[Channel](),
		streamCreator:       nil,
		maxPacketSize:       maxPacketsize,
		channelsManager:     newChannelsManager(),
	}
	roundTripper.StreamHijacker = func(frameType http3.FrameType, qconn quic.Connection, stream quic.Stream, err error) (bool, error) {
		if err != nil {
			return false, err
		}
		if frameType != SSH_FRAME_TYPE {
			return false, nil
		}

		channelInfo, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
		if err != nil {
			return false, err
		}

		newChannel := NewChannel(channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream}, stream, nil, conv.channelsManager, false, false, true, defaultDatagramsQueueSize, nil)
		newChannel.setDatagramSender(func(datagram []byte) error {
			buf := util.AppendVarInt(nil, uint64(conv.controlStream.StreamID()))
			buf = util.AppendVarInt(buf, newChannel.ChannelID())
			buf = append(buf, datagram...)
			return conv.datagramSender.SendDatagram(buf)
		})
		conv.channelsAcceptQueue.Add(newChannel)
		return true, nil
	}
	rsp, err := roundTripper.RoundTripOpt(req, http3.RoundTripOpt{DontCloseRequestStream: true})
	if err != nil {
		return nil, err
	}

	if rsp.StatusCode == 200 {
		conv.controlStream = rsp.Body.(http3.HTTPStreamer).HTTPStream()
		conv.streamCreator = rsp.Body.(http3.Hijacker).StreamCreator()
		return conv, nil
	} else {
		return nil, fmt.Errorf("returned non-200 status code: %d", rsp.StatusCode)
	}
}

func NewServerConversation(controlStream http3.Stream, streamCreator http3.StreamCreator, maxPacketsize uint64) *Conversation {
	conv := &Conversation{
		controlStream:       controlStream,
		channelsAcceptQueue: util.NewAcceptQueue[Channel](),
		streamCreator:       streamCreator,
		maxPacketSize:       maxPacketsize,
		channelsManager:     newChannelsManager(),
	}
	return conv
}

type StreamByteReader struct {
	http3.Stream
}

func (r *StreamByteReader) ReadByte() (byte, error) {
	buf := [1]byte{0}
	_, err := r.Stream.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (c *Conversation) OpenChannel(channelType string, maxPacketSize uint64, datagramsQueueSize uint64) (Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), uint64(str.StreamID()), channelType, maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, nil)
	c.channelsManager.addChannel(channel)
	return channel, nil
}

func (c *Conversation) OpenUDPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), uint64(str.StreamID()), "direct-udp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}

func (c *Conversation) AcceptChannel(ctx context.Context) (Channel, error) {
	for {
		if channel := c.channelsAcceptQueue.Next(); channel != nil {
			channel.confirmChannel(c.maxPacketSize)
			c.channelsManager.addChannel(channel)
			return channel, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.channelsAcceptQueue.Chan():
		}
	}

}

// blocks until the datagram is added
// the first field must be the channel ID
func (c *Conversation) AddDatagram(ctx context.Context, datagram []byte) error {
	buf := &util.BytesReadCloser{Reader: bytes.NewReader(datagram)}
	channelID, err := util.ReadVarInt(buf)
	if err != nil {
		return err
	}
	channel, ok := c.channelsManager.getChannel(channelID)
	if !ok {
		return util.ChannelNotFound{ChannelID: channelID}
	}
	return channel.addDatagram(ctx, datagram[buf.Len():])
}

func (c *Conversation) Close() {
	c.controlStream.Close()
}
