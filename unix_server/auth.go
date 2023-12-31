package unix_server

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/francoismichel/h3sh"
	"github.com/francoismichel/h3sh/util/unix_util"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

func HandleAuths(ctx context.Context, enablePasswordLogin bool, defaultMaxPacketSize uint64, handlerFunc h3sh.AuthenticatedHandlerFunc) (http.HandlerFunc, error) {
	if runtime.GOOS != "linux" && enablePasswordLogin {
		return nil, fmt.Errorf("password login not supported on %s/%s systems", runtime.GOOS, runtime.GOARCH)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		defer w.(http.Flusher).Flush()
		w.Header().Set("Server", h3sh.GetCurrentVersion())
		major, minor, patch, err := h3sh.ParseVersion(r.UserAgent())
		log.Debug().Msgf("received request from User-Agent %s (major %d, minor %d, patch %d)", r.UserAgent(), major, minor, patch)
		// currently apply strict version rules
		if err != nil || major != h3sh.MAJOR || minor != h3sh.MINOR {
			w.WriteHeader(http.StatusForbidden)
			if err == nil {
				w.Write([]byte(fmt.Sprintf("Unsupported version: %d.%d.%d not supported by server in version %s", major, minor, patch, h3sh.GetCurrentVersion())))
			} else {
				w.Write([]byte("Unsupported user-agent"))
			}
			return
		}
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
		conv, err := h3sh.NewServerConversation(ctx, str, qconn, qconn, defaultMaxPacketSize)
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
			HandleBearerAuth(username, base64ConvID, HandleJWTAuth(username, conv, handlerFunc))(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}, nil
}

func HandleBasicAuth(handlerFunc h3sh.AuthenticatedHandlerFunc, conv *h3sh.Conversation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ok, err := unix_util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			if err != nil {
				log.Error().Msgf("user authentication failed: %s", err)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, conv, w, r)
	}
}
