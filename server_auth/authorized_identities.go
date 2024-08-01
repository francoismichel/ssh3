package server_auth

import (
	"bufio"
	"context"
	"crypto"
	"fmt"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/internal"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/rs/zerolog/log"

	"golang.org/x/crypto/ssh"

	"github.com/golang-jwt/jwt/v5"
)

type PubKeyIdentity struct {
	username string
	pubkey   crypto.PublicKey
}

func DefaultIdentitiesFileNames(user *unix_util.User) []string {
	return []string{path.Join(user.Dir, ".ssh3", "authorized_identities"), path.Join(user.Dir, ".ssh", "authorized_keys")}
}

func (i *PubKeyIdentity) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	switch candidate := genericCandidate.(type) {
	case util.JWTTokenString:
		token, err := jwt.Parse(candidate.Token, func(unvalidatedToken *jwt.Token) (interface{}, error) {
			switch unvalidatedToken.Method.Alg() {
			case "RS256", "EdDSA", "ES256":
				return i.pubkey, nil
			}
			return nil, fmt.Errorf("unsupported signature algorithm '%s' for %T", unvalidatedToken.Method.Alg(), i)
		},
			jwt.WithIssuer(i.username),
			jwt.WithSubject("ssh3"),
			jwt.WithIssuedAt(),
			jwt.WithAudience("unused"),
			jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}))
		if err != nil || !token.Valid {
			log.Error().Msgf("invalid private key token: %s", err)
			return false
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if _, ok = claims["exp"]; !ok {
				return false
			}
			if clientId, ok := claims["client_id"]; !ok || clientId != fmt.Sprintf("ssh3-%s", i.username) {
				return false
			}
			if jti, ok := claims["jti"]; !ok || jti != base64ConversationID {
				log.Error().Msgf("rsa verification failed: the jti claim does not contain the base64-encoded conversation ID")
				return false
			}
			// jti not checked yet
		} else {
			fmt.Println(err)
		}

		return true
	default:
		return false
	}
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
		token, err := auth.VerifyRawToken(context.Background(), i.clientID, i.issuerURL, candidate.Token)
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

type WrappedPluginIdentity struct {
	auth.RequestIdentityVerifier
}

func (w *WrappedPluginIdentity) Verify(genericCandidate interface{}, base64ConversationID string) bool {
	switch candidate := genericCandidate.(type) {
	case *http.Request:
		return w.RequestIdentityVerifier.Verify(candidate, base64ConversationID)
	}
	return false
}

func ParseIdentity(user *unix_util.User, identityStr string) (auth.IdentityVerifier, error) {
	identities := internal.FindIdentitiesFromAuthorizedIdentityString(user.Username, identityStr)
	log.Debug().Msgf("found %d identities from plugins", len(identities))
	if len(identities) > 0 {
		log.Debug().Msgf("apply the first found identity")
		return &WrappedPluginIdentity{RequestIdentityVerifier: identities[0]}, nil
	}
	out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	if err == nil {
		log.Debug().Msg("parsing ssh authorized key")
		switch out.Type() {
		case "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519":
			log.Debug().Msgf("parsing %s identity", out.Type())
			cryptoPublicKey := out.(ssh.CryptoPublicKey)
			return &PubKeyIdentity{username: user.Username, pubkey: cryptoPublicKey.CryptoPublicKey()}, nil

		default:
			return nil, fmt.Errorf("SSH authorized identity \"%s\" not implemented", out.Type())
		}
	}
	// it is not an SSH key
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
		return &OpenIDConnectIdentity{
			clientID:  clientID,
			issuerURL: issuerURL,
			email:     email,
		}, nil
	}
	// either error or identity not implemented
	return nil, fmt.Errorf("unknown identity format")
}

func ParseAuthorizedIdentitiesFile(user *unix_util.User, file *os.File) (identities []auth.IdentityVerifier, err error) {
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
		identity, err := ParseIdentity(user, line)
		if err == nil {
			identities = append(identities, identity)
		} else {
			log.Error().Msgf("cannot parse identity line: %s: %s", err.Error(), line)
		}
	}
	return identities, nil
}

func GetAuthorizedIdentities(user *unix_util.User) ([]auth.IdentityVerifier, error) {
	filenames := DefaultIdentitiesFileNames(user)
	var identities []auth.IdentityVerifier
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
