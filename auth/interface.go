package auth

import (
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

/*
 * In ssh3, authorized_keys are replaced by authorized_identities where a use can specify classical
 * public keys as well as other authentication and authorization methods such as OAUTH2 and SAML 2.0
 *
 */
type IdentityVerifier interface {
	// returns whether the provided candidate contains a sufficient proof to
	// be considered as equivalent to this identity
	Verify(candidate interface{}, base64ConversationID string) bool
}

type RequestIdentityVerifier interface {
	Verify(request *http.Request, base64ConversationID string) bool
}

// parses an AuthorizedIdentity line (`identityStr`). Returns a new Identity and a nil error if the
// line was successfully parsed. Returns a nil identity and a nil error if the line format is unknown
// to the plugin. Returns a non-nil error if any other error that is worth to be logged occurs.
//
// plugins are currently a single function so that they are completely stateless
type ServerAuthPlugin func(username string, identityStr string) (RequestIdentityVerifier, error)

// Updates `request` with the correct authentication material so that an SSH3 conversation
// can be established by performing the request
type ClientAuthPlugin func(request *http.Request, roundTripper *http3.RoundTripper) error
