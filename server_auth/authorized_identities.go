package server_auth

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/oidc"
	"github.com/francoismichel/ssh3/internal"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/rs/zerolog/log"
)

type IdentityVerifier interface {
	// returns whether the provided candidate contains a sufficient proof to
	// be considered as equivalent to this identity
	Verify(candidate interface{}, base64ConversationID string) bool
}

func DefaultIdentitiesFileNames(user *unix_util.User) []string {
	return []string{path.Join(user.Dir, ".ssh3", "authorized_identities"), path.Join(user.Dir, ".ssh", "authorized_keys")}
}

type OpenIDConnectIdentity struct {
	clientID  string
	issuerURL string
	email     string
}

func (i *OpenIDConnectIdentity) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	// TODO: verify that the base64ConversationID is also present in the token
	log.Debug().Msgf("verifying openid connect idenitity")
	switch candidate := genericCandidate.(type) {
	case util.JWTTokenString:
		token, err := oidc.VerifyRawToken(context.Background(), i.clientID, i.issuerURL, candidate.Token)
		if err != nil {
			log.Error().Msgf("cannot verify raw token: %s", err.Error())
			return false
		}

		log.Debug().Msgf("token signature verification successful")

		if token.Issuer != i.issuerURL {
			log.Error().Msgf("cannot verify idendity: bad issuer: %s != %s", token.Issuer, i.issuerURL)
			return false
		}

		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := token.Claims(&claims); err != nil {
			log.Error().Msgf("error verifying claims: %s", err)
			return false
		}

		valid := token != nil && claims.EmailVerified && claims.Email == i.email

		if !valid {
			log.Error().Msgf("invalid token: email should be: %s received claims: %+v", i.email, claims)
		}

		return valid
	default:
		return false
	}
}

type WrappedPluginVerifier struct {
	auth.RequestIdentityVerifier
}

func (w *WrappedPluginVerifier) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	switch candidate := genericCandidate.(type) {
	case *http.Request:
		return w.RequestIdentityVerifier.Verify(candidate, base64ConversationID)
	}
	return false
}

func ParseIdentity(user *unix_util.User, identityStr string) (ret []IdentityVerifier, err error) {
	pluginIdentities := internal.FindIdentitiesFromAuthorizedIdentityString(user.Username, identityStr)
	log.Debug().Msgf("found %d identities from plugins", len(pluginIdentities))
	for _, pluginIdentity := range pluginIdentities {
		ret = append(ret, &WrappedPluginVerifier{RequestIdentityVerifier: pluginIdentity})
	}
	// now parse the oidc identity which is not implemented by a plugin yet
	if strings.HasPrefix(identityStr, "oidc") {
		nExpectedTokens := 4
		log.Debug().Msg("parsing oidc identity")
		tokens := strings.Fields(identityStr)
		if len(tokens) != nExpectedTokens {
			return nil, fmt.Errorf("bad identity format for oidc identity, %d tokens instead of the %d expected tokens, identity: %s",
				len(tokens),
				nExpectedTokens,
				identityStr)
		}
		clientID := tokens[1]
		issuerURL := tokens[2]
		email := tokens[3]
		log.Debug().Msgf("oidc identity parsing success: client_id: %s, issuer_url: %s, email: %s", clientID, issuerURL, email)
		ret = append(ret, &OpenIDConnectIdentity{
			clientID:  clientID,
			issuerURL: issuerURL,
			email:     email,
		})
	}
	if len(ret) == 0 {
		// either error or identity not implemented
		return nil, fmt.Errorf("unknown identity format")
	}
	return ret, nil
}

func ParseAuthorizedIdentitiesFile(user *unix_util.User, file *os.File) (identities []IdentityVerifier, err error) {
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber += 1
		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			log.Info().Msgf("%s:%d: skip empty line", file.Name(), lineNumber)
			continue
		} else if line[0] == '#' {
			// commented line
			log.Info().Msgf("%s:%d: skip commented identity", file.Name(), lineNumber)
			continue
		}
		parsedIdentities, err := ParseIdentity(user, line)
		if err == nil {
			identities = append(identities, parsedIdentities...)
		} else {
			log.Error().Msgf("cannot parse identity line: %s: %s", err.Error(), line)
		}
	}
	return identities, nil
}

func GetAuthorizedIdentities(user *unix_util.User) ([]IdentityVerifier, error) {
	filenames := DefaultIdentitiesFileNames(user)
	var identities []IdentityVerifier
	for _, filename := range filenames {
		identitiesFile, err := os.Open(filename)
		if err == nil {
			newIdentities, err := ParseAuthorizedIdentitiesFile(user, identitiesFile)
			if err != nil {
				// TODO: logging
				log.Error().Msgf("error when parsing authorized identities: %s", err)
				return nil, err
			}
			identities = append(identities, newIdentities...)
		} else if !os.IsNotExist(err) {
			log.Error().Msgf("error could not open %s: %s", filename, err)
			return nil, err
		}
	}
	return identities, nil
}
