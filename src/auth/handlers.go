package auth

import (
	"net/http"
	"os"
	"ssh3/src/util"
)

type AuthenticatedHandlerFunc func(authenticatedUserName string, w http.ResponseWriter, r *http.Request)

type UnauthenticatedBearerFunc func(unauthenticatedBearerString string, w http.ResponseWriter, r *http.Request)


// BearerAuth returns the bearer token
// Authorization header, if the request uses HTTP Basic Authentication.
// See RFC 2617, Section 2.
func BearerAuth(r *http.Request) (bearer string, ok bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	return parseBearerAuth(auth)
}

// parseBearerAuth parses an HTTP Bearer Authentication string.
func parseBearerAuth(auth string) (bearer string, ok bool) {
	const prefix = "Bearer "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !util.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	// TODO: maybe validate the encoding format of the JWT token (at least verify that
	// it is base64-encoded)
	return string(auth[len(prefix):]), true
}

func HandleBearerAuth(username string, handlerFunc UnauthenticatedBearerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerString, ok := BearerAuth(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(bearerString, w, r)
	}
}

// currently only supports RS256 and ES256 signing algorithms
func HandleJWTAuth(username string, handlerFunc AuthenticatedHandlerFunc) UnauthenticatedBearerFunc {
	return func(unauthenticatedBearerString string, w http.ResponseWriter, r *http.Request) {
		user, err := GetUser(username)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identitiesFile, err := os.Open(DefaultIdentitiesFileName(user))
		if err != nil {
			// TODO: logging
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identities, err := ParseAuthorizedIdentitiesFile(user, identitiesFile)
		if err != nil {
			// TODO: logging
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		for _, identity := range identities {
			verified := identity.Verify(JWTTokenString{Token: unauthenticatedBearerString})
			if verified {
				// authentication successful
				handlerFunc(username, w, r)
				return
			}
		}

		// TODO: logging
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}
