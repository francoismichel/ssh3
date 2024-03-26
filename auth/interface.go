package auth

/*
 * In ssh3, authorized_keys are replaced by authorized_identities where a use can specify classical
 * public keys as well as other authentication and authorization methods such as OAUTH2 and SAML 2.0
 *
 */
type Identity interface {
	// returns whether those the provided candidate contains a sufficient proof to
	// be considered as equivalent to this identity
	Verify(candidate interface{}, base64ConversationID string) bool
}

// parses an AuthorizedIdentity line (`identityStr`). Returns a new Identity and a nil error if the
// line was successfully parsed. Returns a nil identity and a nil error if the line format is unknown
// to the plugin. Returns a non-nil error if any other error that is worth to be logged occurs.
//
// plugins are currently a single function so that they are completely stateless
type ServerAuthPlugin func(username string, identityStr string) (Identity, error)
