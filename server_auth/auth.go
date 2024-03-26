package server_auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

func HandleAuths(ctx context.Context, enablePasswordLogin bool, defaultMaxPacketSize uint64, handlerFunc ssh3.AuthenticatedHandlerFunc) (http.HandlerFunc, error) {
	if runtime.GOOS != "linux" && enablePasswordLogin {
		return nil, fmt.Errorf("password login not supported on %s/%s systems", runtime.GOOS, runtime.GOARCH)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		peerVersion, err := ssh3.ParseVersionString(r.UserAgent())
		log.Debug().Msgf("received request from User-Agent %s", r.UserAgent())
		log.Debug().Msgf("peer version: protocol version %s, software version %s", peerVersion.GetProtocolVersion(), peerVersion.GetSoftwareVersion())
		// currently apply strict version rules
		if err != nil {
			http.Error(w, fmt.Sprintf("Unsupported user-agent: %s", r.UserAgent()[:100]), http.StatusForbidden)
			return
		}
		if !ssh3.IsVersionSupported(peerVersion) {
			http.Error(w, fmt.Sprintf("Unsupported version: %s not supported by server with version %s", peerVersion.GetProtocolVersion(), ssh3.ThisVersion().GetProtocolVersion()), http.StatusForbidden)
			return
		}
		// Only call Flush() here, as calling flush prevents from adding the Content-Length header to the response
		// The Content-Length can be useful upon receiving an error response
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
		conv, err := ssh3.NewServerConversation(ctx, str, qconn, qconn, defaultMaxPacketSize, peerVersion)
		if err != nil {
			log.Error().Msgf("could not create new server conversation")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		convID := conv.ConversationID()
		base64ConvID := base64.StdEncoding.EncodeToString(convID[:])

		username := r.URL.User.Username()
		if username == "" {
			username = r.URL.Query().Get("user")
		}
		user, err := unix_util.GetUser(username)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identityVerifiers, err := GetAuthorizedIdentities(user)
		if err != nil {
			log.Error().Msgf("error in JWT auth handling when retrieving authorized identities: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// first, handle the HTTP request verifiers (often plugins)
		for _, abstractVerifier := range identityVerifiers {
			switch verifier := abstractVerifier.(type) {
			case auth.RequestIdentityVerifier:
				if verifier.Verify(r, base64ConvID) {
					handlerFunc(username, conv, w, r)
					return
				}
			}
		}

		authorization := r.Header.Get("Authorization")
		if enablePasswordLogin && strings.HasPrefix(authorization, "Basic ") {
			HandleBasicAuth(handlerFunc, conv)(w, r)
		} else if strings.HasPrefix(authorization, "Bearer ") {
			HandleBearerAuth(username, base64ConvID, HandleJWTAuth(username, conv, identityVerifiers, handlerFunc))(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}, nil
}

func HandleBasicAuth(handlerFunc ssh3.AuthenticatedHandlerFunc, conv *ssh3.Conversation) http.HandlerFunc {
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
