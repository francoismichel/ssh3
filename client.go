package ssh3

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path"
	"ssh3/auth"
	"ssh3/util"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kevinburke/ssh_config"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)


type PasswordAuthMethod struct{}
type OidcAuthMethod struct {
	doPKCE    bool
	config    *auth.OIDCConfig
}

func (m *OidcAuthMethod) OIDCConfig() *auth.OIDCConfig {
	return m.config
}

type PrivkeyFileAuthMethod struct {
	filename string
}
type AgentAuthMethod struct {
	pubkey ssh.PublicKey
}

func NewPasswordAuthMethod() *PasswordAuthMethod {
	return &PasswordAuthMethod{}
}

func (m *PasswordAuthMethod) IntoIdentity(password string) Identity {
	return passwordIdentity(password)
}

func NewOidcAuthMethod(doPKCE bool, config *auth.OIDCConfig) *OidcAuthMethod {
	return &OidcAuthMethod{
		doPKCE:    doPKCE,
		config:    config,
	}
}

func (m *OidcAuthMethod) IntoIdentity(bearerToken string) Identity {
	return rawBearerTokenIdentity(bearerToken)
}

func NewPrivkeyFileAuthMethod(filename string) *PrivkeyFileAuthMethod {
	return &PrivkeyFileAuthMethod{
		filename: filename,
	}
}

func (m *PrivkeyFileAuthMethod) Filename() string {
	return m.filename
}

// ToIdentityWithoutPassphrase returns an SSH3 identity stored on the provided path.
// It supports the same keys as ssh.ParsePrivateKey
// If the private key is encrypted, it returns an ssh.PassphraseMissingError.
func (m *PrivkeyFileAuthMethod) IntoIdentityWithoutPassphrase() (Identity, error) {
	return m.intoIdentity(nil)
}

// NewPrivKeyFileIdentity returns an SSH3 identity stored on the provided path.
// It supports the same keys as ssh.ParsePrivateKey
// If the passphrase is wrong, it returns an x509.IncorrectPasswordError.
func (m *PrivkeyFileAuthMethod) IntoIdentityPassphrase(passphrase string) (Identity, error) {
	return m.intoIdentity(&passphrase)
}

func (m *PrivkeyFileAuthMethod) intoIdentity(passphrase *string) (Identity, error) {
	
	filename := m.filename
	if strings.HasPrefix(filename, "~/") {
		dirname, _ := os.UserHomeDir()
		filename = path.Join(dirname, filename[2:])	
	}
	pemBytes, err := os.ReadFile(filename)
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
	return &privkeyFileIdentity{
		privkey:       cryptoSigner,
		signingMethod: signingMethod,
	}, nil
}

func NewAgentAuthMethod(pubkey ssh.PublicKey) *AgentAuthMethod {
	return &AgentAuthMethod{
		pubkey: pubkey,
	}
}

// A prerequisite of calling this methiod is that the provided pubkey is explicitly listed by the agent
// This can be verified beforehand by calling agent.List()
func (m *AgentAuthMethod) IntoIdentity(agent agent.ExtendedAgent) Identity {
	return &agentBasedIdentity{
		pubkey: m.pubkey,
		agent:  agent,
	}
}

// a generic way to generate SSH3 identities to populate the HTTP Authorization header
type Identity interface {
	SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error
	// provides an authentication name that can be used as a hint for the server in the url query params
	AuthHint() string
}

// represents private keys stored in a classical file
type privkeyFileIdentity struct {
	privkey       crypto.Signer
	signingMethod jwt.SigningMethod
}

func (i *privkeyFileIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	bearerToken, err := buildJWTBearerToken(i.signingMethod, i.privkey, username, conversation)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

func (i *privkeyFileIdentity) AuthHint() string {
	return "pubkey"
}


type agentSigningMethod struct {
	Agent agent.ExtendedAgent
	Key   ssh.PublicKey
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
type agentBasedIdentity struct {
	pubkey ssh.PublicKey
	agent  agent.ExtendedAgent
}

func (i *agentBasedIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	signingMethod := &agentSigningMethod{
		Agent: i.agent,
		Key:   i.pubkey,
	}

	bearerToken, err := buildJWTBearerToken(signingMethod, i.pubkey, username, conversation)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

func (i *agentBasedIdentity) AuthHint() string {
	return "pubkey"
}

type passwordIdentity string

func (i passwordIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	req.SetBasicAuth(username, string(i))
	return nil
}

func (i passwordIdentity) AuthHint() string {
	return "password"
}


type rawBearerTokenIdentity string

func (i rawBearerTokenIdentity) SetAuthorizationHeader(req *http.Request, username string, conversation *Conversation) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(i)))
	return nil
}

func (i rawBearerTokenIdentity) AuthHint() string {
	return "jwt"
}


func GetConfigForHost(host string, config *ssh_config.Config) (hostname string, port int, user string, authMethodsToTry []interface{}, err error) {
	port = -1
	if config == nil {
		return
	}
	hostname, err = config.Get(host, "HostName")
	if err != nil {
		log.Error().Msgf("Could not get HostName from config: %s", err)
		return
	}
	portStr, err := config.Get(host, "Port")
	if err != nil {
		log.Error().Msgf("Could not get Port from config: %s", err)
		return
	}
	user, err = config.Get(host, "User")
	if err != nil {
		log.Error().Msgf("Could not get User from config: %s", err)
		return
	}
	p, err := strconv.Atoi(portStr)
	if err == nil {
		port = p
	}
	identityFiles, err := config.GetAll(host, "IdentityFile")
	if err != nil {
		log.Error().Msgf("Could not get IdentityFiles from config: %s", err)
		return
	}
	for _, identityFile := range identityFiles {
		authMethodsToTry = append(authMethodsToTry, NewPrivkeyFileAuthMethod(identityFile))
	}
	return hostname, port, user, authMethodsToTry, nil
}

func buildJWTBearerToken(signingMethod jwt.SigningMethod, key interface{}, username string, conversation *Conversation) (string, error) {
	convID := conversation.ConversationID()
	b64ConvID := base64.StdEncoding.EncodeToString(convID[:])
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"iss":       username,
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
		"sub":       "ssh3",
		"aud":       "unused",
		"client_id": fmt.Sprintf("ssh3-%s", username),
		"jti":       b64ConvID,
	})

	// the jwt lib handles "any kind" of crypto signer
	signedString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %s", err)
	}
	return signedString, nil
}
