package auth

import (
	"net/http"
	"ssh3/src/util"
)

type AuthenticatedHandlerFunc func(authenticatedUserName string, w http.ResponseWriter, r *http.Request)

func HandleBasicAuth(handlerFunc AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		ok, err := util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, w, r)
	}
}