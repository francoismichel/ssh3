package linux_server

import (
	"net/http"
	"ssh3/src/auth"
	"ssh3/src/util/linux_util"
	"strings"
)

func HandleAuths(handlerFunc auth.AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if strings.HasPrefix(authorization, "Basic ") {
			HandleBasicAuth(handlerFunc)(w, r)
		} else if strings.HasPrefix(authorization, "Bearer ") {
			username := r.URL.User.Username()
			if username == "" {
				username = r.URL.Query().Get("user")
			}
			auth.HandleBearerAuth(username, auth.HandleJWTAuth(username, handlerFunc))(w, r)
		}
	}
}

func HandleBasicAuth(handlerFunc auth.AuthenticatedHandlerFunc) http.HandlerFunc {
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
		handlerFunc(username, w, r)
	}
}
