package ssh3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3/util"
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
			log.Error().Msgf("bad HTTP frame type: %d", frameType)
			return false, nil
		}

		conversationsManager, ok := ssh3Server.getConversationsManager(qconn)
		if !ok {
			err := fmt.Errorf("could not find SSH3 conversation for new channel %d on conn %+v", stream.StreamID(), qconn)
			log.Error().Msgf("%s", err)
			return false, err
		}

		conversationControlStreamID, channelType, maxPacketSize, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
		if err != nil {
			return false, err
		}

		conversation, ok := conversationsManager.getConversation(conversationControlStreamID)
		if !ok {
			err := fmt.Errorf("could not find SSH3 conversation with control stream id %d for new channel %d", conversationControlStreamID,
				uint64(stream.StreamID()))
			log.Error().Msgf("%s", err)
			return false, err
		}

		channelInfo := &ChannelInfo{
			ConversationID:       conversation.conversationID,
			ConversationStreamID: conversationControlStreamID,
			ChannelID:            uint64(stream.StreamID()),
			ChannelType:          channelType,
			MaxPacketSize:        maxPacketSize,
		}

		newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream},
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

		case "request-reverse-tcp":
			tcpAddrLocal, tcpAddrRemote, err := parseTCPRequestReverseHeader(channelInfo.ChannelID, &StreamByteReader{stream})
			if err != nil {
				return false, err
			}

			newChannel = &TCPReverseForwardingChannelImpl{Channel: newChannel, RemoteAddr: tcpAddrRemote, LocalAddr: tcpAddrLocal}
			//The channel is only used to receive the data featuring the reverse proxy and is closed afterwards
			//In OpenSSH, the client does this by sendinng a GLOBAL_REQUEST "tcpip-forward", but I think in SSH3 global messages are not implemented

			//tcpAddrLocal: Local socket within the server machine where will be proxied a local service at reach of the ssh3 client
			//tcpAddrRemote: The remote socket at reach of the SSH3 client to be proxied within the machine hosting the ssh3 server
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

type AuthenticatedHandlerFunc func(authenticatedUserName string, newConv *Conversation, w http.ResponseWriter, r *http.Request)

type UnauthenticatedBearerFunc func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request)

func (s *Server) GetHTTPHandlerFunc(ctx context.Context) AuthenticatedHandlerFunc {

	return func(authenticatedUsername string, newConv *Conversation, w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("got request: method: %s, URL: %s", r.Method, r.URL.String())
		if r.Method == http.MethodConnect && r.Proto == "ssh3" {
			hijacker, ok := w.(http3.Hijacker)
			if !ok { // should never happen, unless quic-go change their API
				log.Error().Msg("failed to hijack HTTP conversation: is it an HTTP/3 conversation ?")
				return
			}
			streamCreator := hijacker.StreamCreator()
			qconn := streamCreator.(quic.Connection)
			conversationsManager := s.getOrCreateConversationsManager(streamCreator)
			conversationsManager.addConversation(newConv)

			w.WriteHeader(200)

			go func() {
				// TODO: this hijacks the datagrams for the whole quic connection, so the server
				//		 currently does not work for several conversations in the same QUIC connection
				for {
					dgram, err := qconn.ReceiveDatagram(ctx)
					if err != nil {
						if !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
							log.Error().Msgf("could not receive message from conn: %s", err)
						}
						return
					}
					buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
					convID, err := util.ReadVarInt(buf)
					if err != nil {
						log.Error().Msgf("could not read conv id from datagram on conv %d: %s", newConv.controlStream.StreamID(), err)
						return
					}
					if convID == uint64(newConv.controlStream.StreamID()) {
						err = newConv.AddDatagram(ctx, dgram[buf.Size()-int64(buf.Len()):])
						if err != nil {
							switch e := err.(type) {
							case util.ChannelNotFound:
								log.Warn().Msgf("could not find channel %d, queue datagram in the meantime", e.ChannelID)
							default:
								log.Error().Msgf("could not add datagram to conv id %d: %s", newConv.controlStream.StreamID(), err)
								return
							}
						}
					} else {
						log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
					}
				}
			}()
			go func() {
				defer newConv.Close()
				defer conversationsManager.removeConversation(newConv)
				defer s.removeConnection(streamCreator)
				if err := s.conversationHandler(authenticatedUsername, newConv); err != nil {
					if errors.Is(err, context.Canceled) {
						log.Info().Msgf("conversation canceled for conversation id %s, user %s", newConv.ConversationID(), authenticatedUsername)
					} else {
						log.Error().Msgf("error while handing new conversation: %s for user %s: %s", newConv.ConversationID(), authenticatedUsername, err)
					}
					return
				}
			}()
		}
	}
}
