package auth

import (
	"bufio"
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/rs/zerolog/log"

	"golang.org/x/crypto/ssh"

	"github.com/golang-jwt/jwt/v5"
)

// a JWT bearer token, encoded following the JWT specification
type JWTTokenString struct {
	Token string
}

/*
 * In ssh3, authorized_keys are replaced by authorized_identities where a use can specify classical
 * public keys as well as other authentication and authorization methods such as OAUTH2 and SAML 2.0
 *
 */

type Identity interface {
	// returns whether those the provided candidate contains a sufficient proof to
	// be considered as equivalent to this identity
	Verify(candidate interface{}) bool
}

type RSAPubKeyIdentity struct {
	username string
	pubkey   *rsa.PublicKey
}

func DefaultIdentitiesFileName(user *User) string {
	return path.Join(user.Dir, ".ssh3", "authorized_identities")
}

func (i *RSAPubKeyIdentity) Verify(genericCandidate interface{}) bool {
	switch candidate := genericCandidate.(type) {
	case JWTTokenString:
		token, err := jwt.Parse(candidate.Token, func(unvalidatedToken *jwt.Token) (interface{}, error) {
			switch unvalidatedToken.Method.Alg() {
			case "RS256":
				return i.pubkey, nil
			}
			return nil, fmt.Errorf("unsupported signature algorithm '%s' for %T", unvalidatedToken.Method.Alg(), i)
		},
		jwt.WithIssuer(i.username),
		jwt.WithSubject("ssh3"),
		jwt.WithIssuedAt(),
		jwt.WithAudience("unused"),
		jwt.WithValidMethods([]string{"RS256"}))
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
			if jti, ok := claims["jti"]; !ok || jti != "unused" {
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
	email	  string
}

func (i *OpenIDConnectIdentity) Verify(genericCandidate interface{}) bool {
	log.Debug().Msgf("verifying openid connect idenitity")
	switch candidate := genericCandidate.(type) {
	case JWTTokenString:
		token, err := VerifyRawToken(context.Background(), i.clientID, i.issuerURL, candidate.Token)
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

func ParseIdentity(user *User, identityStr string) (Identity, error) {
	out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	if err == nil {
		log.Debug().Msg("parsing ssh authorized key")
		switch out.Type() {
		case "ssh-rsa":
			log.Debug().Msg("parsing ssh-rsa identity")
			cryptoPublicKey := out.(ssh.CryptoPublicKey)
			return &RSAPubKeyIdentity{username: user.Username, pubkey: cryptoPublicKey.CryptoPublicKey().(*rsa.PublicKey)}, nil
		case "ecdsa-sha2-nistp256":
			panic("not implemented")
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
			clientID: clientID,
			issuerURL: issuerURL,
			email: email,
		}, nil
	}
	// either error or identity not implemented
	return nil, fmt.Errorf("unknown identity format")
}

func ParseAuthorizedIdentitiesFile(user *User, file *os.File) (identities []Identity, err error) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		identity, err := ParseIdentity(user, line)
		if err == nil {
			identities = append(identities, identity)
		} else {
			log.Error().Msgf("cannot parse identity line: %s: %s", err.Error(), line)
		}
	}
	return identities, nil
}
