package auth

import (
	"net/http"

	"github.com/francoismichel/ssh3"
	client_config "github.com/francoismichel/ssh3/client/config"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh/agent"
)

/////////////////////////////////////
//		 Server auth plugins	   //
/////////////////////////////////////

// In ssh3, authorized_keys are replaced by authorized_identities where a use can specify classical
// public keys as well as other authentication and authorization methods such as OAUTH2 and SAML 2.0
type RequestIdentityVerifier interface {
	Verify(request *http.Request, base64ConversationID string) bool
}

// parses an AuthorizedIdentity line (`identityStr`). Returns a new Identity and a nil error if the
// line was successfully parsed. Returns a nil identity and a nil error if the line format is unknown
// to the plugin. Returns a non-nil error if any other error that is worth to be logged occurs.
//
// plugins are currently a single function so that they are completely stateless
type ServerAuthPlugin func(username string, identityStr string) (RequestIdentityVerifier, error)

/////////////////////////////////////
//		 Client auth plugins	   //
/////////////////////////////////////

// Updates `request` with the correct authentication material so that an SSH3 conversation
// can be established by performing the request
// if no SSH agent socket if found, sshAgent is nil
type GetClientAuthMethodsFunc func(request *http.Request, sshAgent agent.ExtendedAgent, clientConfig *client_config.Config, roundTripper *http3.RoundTripper) ([]ClientAuthMethod, error)

type ClientAuthMethod interface {
	// PrepareRequestForAuth updated the provided request with the needed headers
	// for authentication.
	// The method must not alter the request method (must always be CONNECT) nor the
	// Host/:origin, User-Agent or :path headers.
	// The agent is the connected SSH agent if it exists, nil otherwise
	// The provided roundTripper can be used to perform requests with the server to prepare
	// the authentication process.
	// username is the username to authenticate
	// conversation is the Conversation we want to establish
	PrepareRequestForAuth(request *http.Request, sshAgent agent.ExtendedAgent, roundTripper *http3.RoundTripper, username string, conversation *ssh3.Conversation) error
}

type ClientAuthPlugin struct {
	// A plugin can define one or more new SSH3 config options.
	// A new option is defined by providing a dedicated option parser.
	// The key in PluginOptions must be a unique name for each option
	// and must not conflict with any existing option
	// (good practice: "<your_repo_name>[-<option_name>]")
	PluginOptions map[client_config.OptionName]client_config.OptionParser

	PluginFunc GetClientAuthMethodsFunc
}
