package ssh3

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"ssh3/src/auth"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"

	"ssh3/src/util"
)

type ServerConversationHandler func(authenticatedUsername string, conversation *Conversation) error

type Server struct {
	maxPacketSize       uint64
	h3Server            *http3.Server
	conversations       map[http3.StreamCreator]*conversationsManager
	conversationHandler ServerConversationHandler
	lock                sync.Mutex
	// conversations map[]
}

// Creates a new server handling http requests for SSH conversations

func NewServer(maxPacketSize uint64, defaultDatagramQueueSize uint64, h3Server *http3.Server, conversationHandler ServerConversationHandler) *Server {
	ssh3Server := &Server{
		maxPacketSize:       maxPacketSize,
		h3Server:            h3Server,
		conversations:       make(map[http3.StreamCreator]*conversationsManager),
		conversationHandler: conversationHandler,
	}

	h3Server.StreamHijacker = func(frameType http3.FrameType, qconn quic.Connection, stream quic.Stream, err error) (bool, error) {
		if err != nil {
			return false, err
		}
		if frameType != SSH_FRAME_TYPE {
			fmt.Println("bad frame type:", frameType)
			return false, nil
		}

		conversationsManager, ok := ssh3Server.getConversationsManager(qconn)
		if !ok {
			return false, fmt.Errorf("could not find SSH3 conversation for new channel %d on conn %+v", stream.StreamID(), qconn)
		}

		channelInfo, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
		if err != nil {
			return false, err
		}

		conversation, ok := conversationsManager.getConversation(util.ConversationID(channelInfo.ConversationID))
		if !ok {
			return false, fmt.Errorf("could not find SSH3 conversation with id %d for new channel %d on conn %+v", channelInfo.ConversationID, channelInfo.ChannelID, qconn)
		}

		newChannel := NewChannel(channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream},
			stream, nil, conversation.channelsManager, false, false, true, defaultDatagramQueueSize, nil)

		switch channelInfo.ChannelType {
		case "direct-udp":
			udpAddr, err := parseUDPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
			if err != nil {
				return false, err
			}
			newChannel.setDatagramSender(conversation.getDatagramSenderForChannel(channelInfo.ChannelID))
			newChannel = &UDPForwardingChannelImpl{Channel: newChannel, RemoteAddr: udpAddr}
		case "direct-tcp":
			tcpAddr, err := parseTCPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
			if err != nil {
				return false, err
			}
			newChannel = &TCPForwardingChannelImpl{Channel: newChannel, RemoteAddr: tcpAddr}
		}
		conversation.channelsAcceptQueue.Add(newChannel)
		return true, nil
	}
	return ssh3Server
}

func (s *Server) getConversationsManager(streamCreator http3.StreamCreator) (*conversationsManager, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversations, ok := s.conversations[streamCreator]
	return conversations, ok
}

func (s *Server) getOrCreateConversationsManager(streamCreator http3.StreamCreator) *conversationsManager {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversationsManager, ok := s.conversations[streamCreator]
	if !ok {
		s.conversations[streamCreator] = newConversationManager(streamCreator)
		conversationsManager = s.conversations[streamCreator]
	}
	return conversationsManager
}

func (s *Server) removeConnection(streamCreator http3.StreamCreator) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.conversations, streamCreator)
}

type SSH3Handler = auth.AuthenticatedHandlerFunc

func (s *Server) GetHTTPHandlerFunc(ctx context.Context) SSH3Handler {

	return func(authenticatedUsername string, w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("got request: method: %s, URL: %s", r.Method, r.URL.String())
		if r.Method == http.MethodConnect && r.Proto == "ssh3" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			str := r.Body.(http3.HTTPStreamer).HTTPStream()

			hijacker, ok := w.(http3.Hijacker)
			if !ok { // should never happen, unless quic-go change their API
				fmt.Fprintf(os.Stderr, "failed to hijack")
				return
			}

			streamCreator := hijacker.StreamCreator()
			qconn := streamCreator.(quic.Connection)
			conv := NewServerConversation(qconn.Context(), str, streamCreator, streamCreator.(quic.Connection), s.maxPacketSize)
			conversationsManager := s.getOrCreateConversationsManager(streamCreator)
			conversationsManager.addConversation(conv)

			go func() {
				// TODO: this hijacks the datagrams for the whole quic connection, so the server
				//		 currently does not work for several conversations in the same QUIC connection
				for {
					dgram, err := qconn.ReceiveMessage(ctx)
					if err != nil {
						log.Error().Msgf("could not receive message from conn: %s", err)
						return
					}
					buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
					convID, err := util.ReadVarInt(buf)
					if err != nil {
						log.Error().Msgf("could not read conv id from datagram on conv %d: %s", conv.controlStream.StreamID(), err)
						return
					}
					if convID == uint64(conv.controlStream.StreamID()) {
						err = conv.AddDatagram(ctx, dgram[buf.Size()-int64(buf.Len()):])
						if err != nil {
							switch e := err.(type) {
							case util.ChannelNotFound:
								log.Warn().Msgf("could not find channel %d, queue datagram in the meantime", e.ChannelID)
							default:
								log.Error().Msgf("could not add datagram to conv id %d: %s", conv.controlStream.StreamID(), err)
								return
							}
						}
					} else {
						log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
					}
				}
			}()
			go func() {
				defer conv.Close()
				defer conversationsManager.removeConversation(conv)
				defer s.removeConnection(streamCreator)
				if err := s.conversationHandler(authenticatedUsername, conv); err != nil {
					fmt.Fprintf(os.Stderr, "error while handing new conversation: %+v", err)
					return
				}
			}()
		}
	}
}
