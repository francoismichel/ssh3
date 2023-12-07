package linux_server

import (
	"context"
	"encoding/base64"
	"net/http"
	ssh3 "ssh3/src"
	"ssh3/src/util/linux_util"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

func HandleAuths(ctx context.Context, enablePasswordLogin bool, defaultMaxPacketSize uint64, handlerFunc ssh3.AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer w.(http.Flusher).Flush()
		hijacker, ok := w.(http3.Hijacker)
		if !ok { // should never happen, unless quic-go change their API
			log.Error().Msgf("failed to hijack")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		streamCreator := hijacker.StreamCreator()
		qconn := streamCreator.(quic.Connection)
		if !qconn.ConnectionState().TLS.HandshakeComplete {
			// do not process early data (0-RTT) when performing authorization
			// to avoid replay attacks
			w.WriteHeader(http.StatusTooEarly)
			return
		}
		str := r.Body.(http3.HTTPStreamer).HTTPStream()
		conv, err := ssh3.NewServerConversation(ctx, str, qconn, qconn, defaultMaxPacketSize)
		if err != nil {
			log.Error().Msgf("could not create new server conversation")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		convID := conv.ConversationID()
		base64ConvID := base64.StdEncoding.EncodeToString(convID[:])
		authorization := r.Header.Get("Authorization")
		if enablePasswordLogin && strings.HasPrefix(authorization, "Basic ") {
			HandleBasicAuth(handlerFunc, conv)(w, r)
		} else if strings.HasPrefix(authorization, "Bearer ") {
			username := r.URL.User.Username()
			if username == "" {
				username = r.URL.Query().Get("user")
			}
			ssh3.HandleBearerAuth(username, base64ConvID, ssh3.HandleJWTAuth(username, conv, handlerFunc))(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}
}

func HandleBasicAuth(handlerFunc ssh3.AuthenticatedHandlerFunc, conv *ssh3.Conversation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ok, err := linux_util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, conv, w, r)
	}
}
