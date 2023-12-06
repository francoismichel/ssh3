package ssh3

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"ssh3/src/util"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)


// a generic way to generate SSH3 identities to populate the HTTP Authorization header
type Identity interface {
	SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error
}


// represents private keys stored in a classical file
type PrivkeyFileIdentity struct {
	privkey	crypto.Signer
	signingMethod jwt.SigningMethod
}

// NewPrivKeyFileIdentity returns an SSH3 identity stored on the provided path.
// It supports the same keys as ssh.ParsePrivateKey
// If the private key is encrypted, it will return an ssh.PassphraseMissingError.
func NewPrivKeyFileIdentity(path string, passphrase *string) (*PrivkeyFileIdentity, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cryptoSigner crypto.Signer
	var signer interface{}
	var ok bool
	if passphrase == nil {
		signer, err = ssh.ParseRawPrivateKey(pemBytes)
	} else {
		signer, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, []byte(*passphrase))
	}
	if err != nil {
		return nil, err
	}
	// transform the abstract type into a crypto.Signer that can be used with the jwt lib
	if cryptoSigner, ok = signer.(crypto.Signer); !ok {
		return nil, fmt.Errorf("the provided key file does not result in a crypto.Signer type")
	}
	signingMethod, err := util.JWTSigningMethodFromCryptoPubkey(cryptoSigner.Public())
	if err != nil {
		return nil, err
	}
	return &PrivkeyFileIdentity{
		privkey: cryptoSigner,
		signingMethod: signingMethod,
	}, nil
}

func (i *PrivkeyFileIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	bearerToken, err := buildJWTBearerToken(i.signingMethod, i.privkey, username, conversation)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}



type agentSigningMethod struct {
	Agent agent.ExtendedAgent
	Key *agent.Key
}

func (m *agentSigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	panic("not implemented")
}

func (m *agentSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	pk, ok := key.(ssh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bad key type: %T instead of ssh.PublicKey", pk)
	}
	signature, err := m.Agent.SignWithFlags(pk, []byte(signingString), agent.SignatureFlagRsaSha256)
	if err != nil {
		return nil, err
	}
	return signature.Blob, nil
}

func (m *agentSigningMethod) Alg() string {
	switch m.Key.Type() {
	case "ssh-rsa":
		return "RS256"
	case "ssh-ed25519":
		return "EdDSA"
	}
	return ""
}


// represents an identity using a running SSH agent
type AgentBasedIdentity struct {
	pubkey *agent.Key
	agent agent.ExtendedAgent
}

func NewAgentBasedIdentity(agent agent.ExtendedAgent, pubkey *agent.Key) *AgentBasedIdentity {
	return &AgentBasedIdentity{
		pubkey: pubkey,
		agent: agent,
	}
}

func (i *AgentBasedIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	signingMethod := &agentSigningMethod{
		Agent: i.agent,
		Key: i.pubkey,
	}

	bearerToken, err := buildJWTBearerToken(signingMethod, i.pubkey, username, conversation)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

type PasswordIdentity string

func (i PasswordIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	req.SetBasicAuth(username, string(i))
	return nil
}

type RawBearerTokenIdentity string
func (i RawBearerTokenIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(i)))
	return nil
}

func buildJWTBearerToken(signingMethod jwt.SigningMethod, key interface{}, username string, conversation *Conversation) (string, error) {
	convID := conversation.ConversationID()
	b64ConvID := base64.StdEncoding.EncodeToString(convID[:])
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"iss": username,
		"iat": jwt.NewNumericDate(time.Now()),
		"exp": jwt.NewNumericDate(time.Now().Add(10*time.Second)),
		"sub": "ssh3",
		"aud": "unused",
		"client_id": fmt.Sprintf("ssh3-%s", username),
		"jti": b64ConvID,
	})

	// the jwt lib handles "any kind" of crypto signer
	signedString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %s", err)
	}
	return signedString, nil
}
