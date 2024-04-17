package auth

import (
	"net/http"

	client_config "github.com/francoismichel/ssh3/client/config"
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
type ClientAuthPluginFunc func(request *http.Request, clientOpts *client_config.Config, roundTripper *http3.RoundTripper) error

type ClientAuthPlugin struct {
	// A plugin can define one or more new SSH3 config options.
	// A new option is defined by providing a dedicated option parser.
	// The key in PluginOptions must be a unique name for each option
	// and must not confict with any existing option
	// (good practice: "<your_repo_name>[-<option_name>]")
	PluginOptions map[client_config.OptionName]client_config.OptionParser

	PluginFunc ClientAuthPluginFunc
}
