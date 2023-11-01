package auth

import (
	"fmt"
	"net/http"
	"ssh3/src/util"
)

type AuthenticatedHandlerFunc func(authenticatedUserName string, w http.ResponseWriter, r *http.Request)

func HandleBasicAuth(handlerFunc AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		fmt.Printf("DEBUG: received user:passwd=%s:%s\n", username, password)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		ok, err := util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			fmt.Printf("DEBUG: ok=%d, err=%+v\n", ok, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, w, r)
	}
}