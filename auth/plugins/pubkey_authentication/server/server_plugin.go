package server_pubkey_authentication

import (
	"crypto"
	"fmt"
	"net/http"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/server_auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

// impements server-side pubkey-based authentication

const PLUGIN_NAME = "github.com/francoismichel/ssh3-server_pubkey_auth"

func init() {
	if err := plugins.RegisterServerAuthPlugin(PLUGIN_NAME, PubkeyAuthPlugin); err != nil {
		log.Error().Msgf("could not register plugin %s: %s", PLUGIN_NAME, err)
	}
}

type PubkeyJWTIdentityVerifier struct {
	username string
	pubkey   crypto.PublicKey
}

func (v *PubkeyJWTIdentityVerifier) Verify(request *http.Request, base64ConversationID string) bool {
	jwtToken, wellFormattedB64Token := server_auth.ParseBearerAuth(request.Header.Get("Authorization"))
	if !wellFormattedB64Token {
		return false
	}

	token, err := jwt.Parse(jwtToken,
		func(unvalidatedToken *jwt.Token) (interface{}, error) {
			log.Debug().Msgf("token method: %s, pubkey = %T %+v", unvalidatedToken.Method.Alg(), v.pubkey, v.pubkey)
			switch unvalidatedToken.Method.Alg() {
			case "RS256", "EdDSA", "ES256":
				return v.pubkey, nil
			}
			return nil, fmt.Errorf("unsupported signature algorithm '%s' for %T", unvalidatedToken.Method.Alg(), v)
		},
		jwt.WithIssuer(v.username),
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
		if clientId, ok := claims["client_id"]; !ok || clientId != fmt.Sprintf("ssh3-%s", v.username) {
			return false
		}
		if jti, ok := claims["jti"]; !ok || jti != base64ConversationID {
			log.Error().Msgf("rsa verification failed: the jti claim does not contain the base64-encoded conversation ID")
			return false
		}
	} else {
		log.Error().Msgf("bad JWT claims type: %T", token.Claims)
		return false
	}

	return true
}

func PubkeyAuthPlugin(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
	log.Debug().Msgf("pubkey auth plugin: parse identity string")
	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	// we should not return an error when the format does not match a public key, we should just return a nil RequestIdentityVerifier
	if err != nil {
		log.Debug().Msgf("the identity string is not a compatible pubkey string")
		return nil, nil
	}

	log.Debug().Msg("parsing ssh authorized key")
	switch pubkey.Type() {
	case "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519":
		log.Debug().Msgf("parsing %s identity", pubkey.Type())
		cryptoPublicKey := pubkey.(ssh.CryptoPublicKey)
		return &PubkeyJWTIdentityVerifier{
			pubkey:   cryptoPublicKey.CryptoPublicKey(),
			username: username,
		}, nil

	default:
		return nil, fmt.Errorf("SSH authorized identity \"%s\" not implemented", pubkey.Type())
	}
}
