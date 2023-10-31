package ssh3

import (
	"context"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const SSH_FRAME_TYPE = 0xaf3627e6

// Accept queue copied from https://github.com/quic-go/webtransport-go/blob/master/session.go
type acceptQueue[T any] struct {
	mx sync.Mutex
	// The channel is used to notify consumers (via Chan) about new incoming items.
	// Needs to be buffered to preserve the notification if an item is enqueued
	// between a call to Next and to Chan.
	c chan struct{}
	// Contains all the streams waiting to be accepted.
	// There's no explicit limit to the length of the queue, but it is implicitly
	// limited by the stream flow control provided by QUIC.
	queue []T
}

func newAcceptQueue[T any]() *acceptQueue[T] {
	return &acceptQueue[T]{c: make(chan struct{}, 1)}
}

func (q *acceptQueue[T]) Add(str T) {
	q.mx.Lock()
	q.queue = append(q.queue, str)
	q.mx.Unlock()

	select {
	case q.c <- struct{}{}:
	default:
	}
}

func (q *acceptQueue[T]) Next() T {
	q.mx.Lock()
	defer q.mx.Unlock()

	if len(q.queue) == 0 {
		return *new(T)
	}
	str := q.queue[0]
	q.queue = q.queue[1:]
	return str
}

func (q *acceptQueue[T]) Chan() <-chan struct{} { return q.c }


type Conversation struct {
	controlStream http3.Stream
	maxPacketSize uint64
	streamCreator http3.StreamCreator

	channelsAcceptQueue *acceptQueue[*Channel]
}

func NewClientConversation(controlStream http3.Stream, roundTripper *http3.RoundTripper, streamCreator http3.StreamCreator, maxPacketsize uint64) *Conversation {
	conv := &Conversation{
		controlStream: controlStream,
		channelsAcceptQueue: newAcceptQueue[*Channel](),
		streamCreator: streamCreator,
		maxPacketSize: maxPacketsize,
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

		newChannel := NewChannel(channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream}, stream, false, false, true)
		conv.channelsAcceptQueue.Add(newChannel)
		return true, nil
	}
	return conv
}

func NewServerConversation(controlStream http3.Stream, streamCreator http3.StreamCreator, maxPacketsize uint64) *Conversation {
	conv := &Conversation{
		controlStream: controlStream,
		channelsAcceptQueue: newAcceptQueue[*Channel](),
		streamCreator: streamCreator,
		maxPacketSize: maxPacketsize,
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

func (c *Conversation) OpenChannel(channelType string, maxPacketSize uint64) (*Channel, error) {
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	return NewChannel(uint64(c.controlStream.StreamID()), uint64(str.StreamID()), channelType, maxPacketSize, &StreamByteReader{str}, str, true, true, false), nil
}


func (c *Conversation) AcceptChannel(ctx context.Context) (*Channel, error) {
	for {
		if channel := c.channelsAcceptQueue.Next(); channel != nil {
			channel.confirmChannel(c.maxPacketSize)
			return channel, nil
		}
		select {
		case <- ctx.Done():
			return nil, ctx.Err()
		case <- c.channelsAcceptQueue.Chan():
		}
	}
	
}

func (c *Conversation) Close() {
	c.controlStream.Close()
}