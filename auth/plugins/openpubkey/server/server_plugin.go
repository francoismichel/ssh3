package server_openpubkey_authentication

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/server_auth"
	"github.com/rs/zerolog/log"
)

const PLUGIN_NAME = "github.com/openpubkey/ssh3-server_openpubkey_auth"

func init() {
	if err := plugins.RegisterServerAuthPlugin(PLUGIN_NAME, OpenPubkeyAuthPlugin); err != nil {
		log.Error().Msgf("could not register plugin %s: %s", PLUGIN_NAME, err)
	}
}

type OpenPubkeyIdentityVerifier struct {
	username     string
	clientIdOidc string
	issuerOidc   string
	email        string
}

func (v *OpenPubkeyIdentityVerifier) Verify(request *http.Request, base64ConversationID string) bool {
	authStr, wellFormattedB64Token := server_auth.ParseBearerAuth(request.Header.Get("Authorization"))
	if !wellFormattedB64Token {
		log.Error().Msgf("!wellFormattedB64Token %s ", request.Header.Get("Authorization"))
		return false
	}

	authStrArr := strings.Split(authStr, "#")
	if len(authStrArr) != 2 {
		log.Error().Msgf("authStr not properly formed")
		return false
	}
	jwtToken := authStrArr[0]
	pktCom := authStrArr[1]

	var op providers.OpenIdProvider
	// Add new openID Provider support here
	switch v.issuerOidc {
	case "https://accounts.google.com":
		opOptions := providers.GetDefaultGoogleOpOptions()
		opOptions.ClientID = v.clientIdOidc
		opOptions.GQSign = false
		op = providers.NewGoogleOpWithOptions(opOptions)
	default:
		log.Error().Msgf("openID Provider is not supported: issuer=%s", v.issuerOidc)
		return false
	}
	opkVerifier, err := verifier.New(op)
	if err != nil {
		log.Error().Msgf("failed to configure openpubkey verifier: %s", err)
		return false
	}
	pkt, err := pktoken.NewFromCompact([]byte(pktCom))
	if err != nil {
		log.Error().Msgf("failed to deserialize compact PK Token: %s", err)
		return false
	}
	err = opkVerifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		log.Error().Msgf("failed to verify PK Token: %s", err)
		return false
	}

	if _, err := pkt.VerifySignedMessage([]byte(jwtToken)); err != nil {
		log.Error().Msgf("OpenPubkey JWT signature verification failed: %s", err)
		return false
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		log.Error().Msgf("OpenPubkey CIC is wrong: %s", err)
		return false
	}

	upk := cic.PublicKey()
	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err := upk.Raw(&rawkey); err != nil {
		log.Error().Msgf("OpenPubkey CIC is wrong: %s", err)
		return false
	}

	log.Error().Msgf("OpenPubkey: Parsing JWT")

	token, err := jwt.Parse(jwtToken,
		func(unvalidatedToken *jwt.Token) (interface{}, error) {
			log.Debug().Msgf("token method: %s, pubkey = %T %+v", unvalidatedToken.Method.Alg(), rawkey, rawkey)
			switch unvalidatedToken.Method.Alg() {
			case "RS256", "EdDSA", "ES256":
				return rawkey, nil
			}
			return nil, fmt.Errorf("unsupported signature algorithm '%s' for %T", unvalidatedToken.Method.Alg(), v)
		},
		jwt.WithIssuer(v.username),
		jwt.WithSubject("ssh3"),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second), // Be forgiving of small clock differences
		jwt.WithAudience("unused"),
		jwt.WithValidMethods([]string{"RS256", "EdDSA", "ES256"}))
	if err != nil || !token.Valid {
		log.Error().Msgf("invalid private key token: %s", err)
		return false
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if _, ok = claims["exp"]; !ok {
			log.Error().Msgf("missing exp")

			return false
		}
		if clientId, ok := claims["client_id"]; !ok || clientId != fmt.Sprintf("ssh3-%s", v.username) {
			log.Error().Msgf("invalid client_id %s", clientId)
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

	log.Info().Msgf("Passed verification")

	return true
}

// OpenPubkeyAuthPlugin takes a username and identityStr from the authorizedIdentity file
// and either rejects the identity string or returns a verifier.
func OpenPubkeyAuthPlugin(username string, identityStr string) (auth.RequestIdentityVerifier, error) {
	log.Debug().Msgf("OpenPubkey auth plugin: parse identity string %s", identityStr)

	identityStrArr := strings.Split(identityStr, " ")
	// TODO: "opk" should be a constant
	if len(identityStrArr) != 4 || identityStrArr[0] != "opk" {
		log.Debug().Msgf("the identity string is not a compatiable openpubkey string, %s", identityStr)
		// we should not return an error when the format does not match a public key, we should just return a nil RequestIdentityVerifier
		return nil, fmt.Errorf("the identity string is not a compatiable openpubkey string, %s", identityStr)
	}
	clientId := identityStrArr[1]
	issuer := identityStrArr[2]
	email := identityStrArr[3]

	log.Debug().Msg("parsing OpenPubkey config")

	return &OpenPubkeyIdentityVerifier{
		username:     username,
		clientIdOidc: clientId,
		issuerOidc:   issuer,
		email:        email,
	}, nil
}
