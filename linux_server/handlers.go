package linux_server

import (
	"net/http"
	"os"
	"ssh3"
	"ssh3/util"
	"ssh3/util/linux_util"

	"github.com/rs/zerolog/log"
)


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

func HandleBearerAuth(username string, base64ConversationID string, handlerFunc ssh3.UnauthenticatedBearerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerString, ok := BearerAuth(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(bearerString, base64ConversationID, w, r)
	}
}

// currently only supports RS256 and EdDSA signing algorithms
func HandleJWTAuth(username string, newConv *ssh3.Conversation, handlerFunc ssh3.AuthenticatedHandlerFunc) ssh3.UnauthenticatedBearerFunc {
	return func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request) {
		user, err := linux_util.GetUser(username)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		filenames := DefaultIdentitiesFileNames(user)
		var identities []Identity
		for _, filename := range filenames {
			identitiesFile, err := os.Open(filename)
			if err == nil {
				newIdentities, err := ParseAuthorizedIdentitiesFile(user, identitiesFile)
				if err != nil {
					// TODO: logging
					log.Error().Msgf("error when parsing authorized identities: %s", err)
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				identities = append(identities, newIdentities...)
			} else if !os.IsNotExist(err) {
				log.Error().Msgf("error could not open %s: %s", filename, err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		for _, identity := range identities {
			verified := identity.Verify(util.JWTTokenString{Token: unauthenticatedBearerString}, base64ConversationID)
			if verified {
				// authentication successful
				handlerFunc(username, newConv, w, r)
				return
			}
		}

		// TODO: logging
		w.WriteHeader(http.StatusUnauthorized)
	}
}
