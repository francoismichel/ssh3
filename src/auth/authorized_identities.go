package auth

import (
	"bufio"
	"crypto/rsa"
	"fmt"
	"os"
	"path"

	"golang.org/x/crypto/ssh"

	"github.com/golang-jwt/jwt/v5"
)

// a JWT bearer token, encoded following the JWT specification
type JWTTokenString struct {
	token string
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

func DefaultIdentitieFileName(user *User) string {
	return path.Join(user.Dir, ".ssh3", "authorized_identities")
}

func (i *RSAPubKeyIdentity) Verify(genericCandidate interface{}) bool {
	switch candidate := genericCandidate.(type) {
	case JWTTokenString:
		token, err := jwt.Parse(candidate.token, func(unvalidatedToken *jwt.Token) (interface{}, error) {
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
			return false
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if _, ok = claims["exp"]; !ok {
				return false
			}
			if clientId, ok := claims["client_id"]; !ok || clientId != i.username {
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

type SAML2Identity struct {
}

func ParseIdentity(user *User, identityStr string) (Identity, error) {
	out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(identityStr))
	if err == nil {
		switch out.Type() {
		case "ssh-rsa":
			cryptoPublicKey := out.(ssh.CryptoPublicKey)
			return &RSAPubKeyIdentity{username: user.Username, pubkey: cryptoPublicKey.CryptoPublicKey().(*rsa.PublicKey)}, nil
		case "ecdsa-sha2-nistp256":
			panic("not implemented")
		}
	}
	// either error or identity not implemented
	panic("not implemented")
}

func ParseAuthorizedIdentitiesFile(user *User, file *os.File) (identities []Identity, err error) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		identity, err := ParseIdentity(user, line)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}
