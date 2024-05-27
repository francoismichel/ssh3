package server_openpubkey_authentication

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/server_auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

const PLUGIN_NAME = "github.com/openpubkey/ssh3-server_openpubkey_auth"

func init() {
	if err := plugins.RegisterServerAuthPlugin(PLUGIN_NAME, OpenPubkeyAuthPlugin); err != nil {
		log.Error().Msgf("could not register plugin %s: %s", PLUGIN_NAME, err)
	}
}

type OpenPubkeyIdentityVerifier struct {
	username string
	// pubkey   crypto.PublicKey
}

func (v *OpenPubkeyIdentityVerifier) Verify(request *http.Request, base64ConversationID string) bool {
	jwtToken, wellFormattedB64Token := server_auth.ParseBearerAuth(request.Header.Get("Authorization"))
	if !wellFormattedB64Token {
		return false
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithIssuer(v.username),
		jwt.WithSubject("ssh3"),
		jwt.WithIssuedAt(),
		jwt.WithAudience("unused"),
		jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}),
	)

	unvalidatedToken, _, err := parser.ParseUnverified(jwtToken, claims)
	if err != nil {
		log.Error().Msgf("invalid OpenPubkey JWT: %s", err)
		return false
	}
	if claims, ok := unvalidatedToken.Claims.(jwt.MapClaims); ok {
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
		if pktCom, ok := claims["pkt"]; ok {
			// TODO: determine OP to use from config rather than just assume Google
			opOptions := providers.GetDefaultGoogleOpOptions()
			opOptions.GQSign = false
			op := providers.NewGoogleOpWithOptions(opOptions)
			opkVerifier, err := verifier.New(op)

			if err != nil {
				log.Error().Msgf("failed to configure openpubkey verifier: %s", err)
				return false
			}
			pkt, err := pktoken.NewFromCompact([]byte(pktCom.(string)))
			if err != nil {
				log.Error().Msgf("failed to deserialize compact PK Token: %s", err)
				return false
			}
			err = opkVerifier.VerifyPKToken(context.Background(), pkt)
			if err != nil {
				log.Error().Msgf("failed to verify PK Token: %s", err)
				return false
			}

			// _, err = pkt.VerifySignedMessage([]byte(jwtToken))
			// if err != nil {
			// 	log.Error().Msgf("JWT verification failure: %s", err)
			// 	return false
			// }

			cic, err := pkt.GetCicValues()
			if err != nil {
				log.Error().Msgf("OpenPubkey CIC deserialization failure: %s", err)
				return false
			}

			//TODO: Check algorithm
			//TODO: Verify this inside OpenPubkey
			_, err = jws.Verify([]byte(jwtToken), jws.WithKey(cic.PublicKey().Algorithm(), cic.PublicKey()))
			if err != nil {
				log.Error().Msgf("OpenPubkey JWT signature verification failed: %s", err)
				return false
			}

			log.Debug().Msgf("PK Token verified")

		} else {
			return false
		}
	} else {
		log.Error().Msgf("bad JWT claims type: %T", unvalidatedToken.Claims)
		return false
	}

	log.Info().Msgf("Passed verification")

	return true
}

func OpenPubkeyAuthPlugin(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
	log.Debug().Msgf("OpenPubkey auth plugin: parse identity string")
	// pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	// // we should not return an error when the format does not match a public key, we should just return a nil RequestIdentityVerifier
	// if err != nil {
	// 	log.Debug().Msgf("the identity string is not a compatible pubkey string")
	// 	return nil, nil
	// }

	log.Debug().Msg("parsing OpenPubkey config")
	// switch pubkey.Type() {
	// case "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519":
	// 	log.Debug().Msgf("parsing %s identity", pubkey.Type())
	// 	cryptoPublicKey := pubkey.(ssh.CryptoPublicKey)
	// 	return &OpenPubkeyIdentityVerifier{
	// 		pubkey:   cryptoPublicKey.CryptoPublicKey(),
	// 		username: username,
	// 	}, nil

	return &OpenPubkeyIdentityVerifier{
		// pubkey:   cryptoPublicKey.CryptoPublicKey(),
		username: username,
	}, nil

	// default:
	// 	return nil, fmt.Errorf("SSH authorized identity \"%s\" not implemented", pubkey.Type())
	// }
}
