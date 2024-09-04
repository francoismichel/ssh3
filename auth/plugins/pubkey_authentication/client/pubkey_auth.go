package client_pubkey_authentication

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/client/config"
	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func init() {
	plugin := auth.ClientAuthPlugin{
		PluginOptions: map[config.OptionName]config.OptionParser{PUBKEY_OPTION_NAME: &PubkeyOptionParser{}},
		PluginFunc:    pubkeyPluginFunc,
	}
	plugins.RegisterClientAuthPlugin("pubkey_auth", plugin)
}

const PUBKEY_OPTION_NAME = "github.com/francoismichel/ssh3-pubkey_auth"

type PubkeyAuthOption struct {
	filenames []string
}

func (o *PubkeyAuthOption) Filenames() []string {
	return o.filenames
}

type PubkeyOptionParser struct{}

// FlagName implements config.CLIOptionParser.
func (*PubkeyOptionParser) FlagName() string {
	return "pubkey-for-agent"
}

// IsBoolFlag implements config.CLIOptionParser.
func (*PubkeyOptionParser) IsBoolFlag() bool {
	return false
}

// OptionConfigName implements config.OptionParser.
func (*PubkeyOptionParser) OptionConfigName() string {
	return "IdentityFile"
}

// Parse implements config.OptionParser.
func (*PubkeyOptionParser) Parse(values []string) (config.Option, error) {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		log.Warn().Msgf("specified a public key (%s) but no agent is running", values)
	}

	return PubkeyAuthOption{
		filenames: values,
	}, nil
}

// Usage implements config.CLIOptionParser.
func (*PubkeyOptionParser) Usage() string {
	return "if set, use an agent key whose public key matches the one in the specified path"
}

var _ config.CLIOptionParser = &PrivkeyOptionParser{}

// agentSigningMethod implements jwt.SigningMethod to use the SSH agent with the jwt lib
type agentSigningMethod struct {
	agent agent.ExtendedAgent
	key   ssh.PublicKey
	alg   string
}

func NewAgentSigningMethod(agent agent.ExtendedAgent, key ssh.PublicKey) (*agentSigningMethod, error) {
	ret := &agentSigningMethod{
		key:   key,
		agent: agent,
	}
	switch key.Type() {
	case "ssh-rsa":
		ret.alg = "RS256"
	case "ssh-ed25519":
		ret.alg = "EdDSA"
	default:
		return nil, fmt.Errorf("unsupported key type for agent signing method")
	}
	return ret, nil
}

func (m *agentSigningMethod) Verify(signingString string, sig []byte, key interface{}) error {
	panic("not implemented")
}

func (m *agentSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	pk, ok := key.(ssh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bad key type: %T instead of ssh.PublicKey", pk)
	}
	signature, err := m.agent.SignWithFlags(pk, []byte(signingString), agent.SignatureFlagRsaSha256)
	if err != nil {
		return nil, err
	}
	return signature.Blob, nil
}

func (m *agentSigningMethod) Alg() string {
	return m.alg
}

type PubkeyAuthMethod struct {
	*agent.Key
}

func NewPubkeyAuthMethod(pubkey *agent.Key) *PubkeyAuthMethod {
	return &PubkeyAuthMethod{pubkey}
}

// PrepareRequestForAuth implements auth.ClientAuthMethod.
func (m *PubkeyAuthMethod) PrepareRequestForAuth(request *http.Request, sshAgent agent.ExtendedAgent, roundTripper *http3.RoundTripper, username string, conversation *ssh3.Conversation) error {
	log.Debug().Msgf("try agent-based pubkey auth using pubkey %s", m.Key.String())

	signingMethod, err := NewAgentSigningMethod(sshAgent, m.Key)
	if err != nil {
		return err
	}

	bearerToken, err := ssh3.BuildJWTBearerToken(signingMethod, m.Key, username, conversation)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

var pubkeyPluginFunc auth.GetClientAuthMethodsFunc = func(request *http.Request, sshAgent agent.ExtendedAgent, clientConfig *config.Config, roundTripper *http3.RoundTripper) ([]auth.ClientAuthMethod, error) {
	var agentKeys []*agent.Key
	var err error
	if sshAgent != nil {
		agentKeys, err = sshAgent.List()
		if err != nil {
			log.Warn().Msgf("error when interacting with SSH agent: %s", err)
			return nil, nil
		}
	} else {
		log.Warn().Msgf("no SSH agent is connected")
	}
	for _, opt := range clientConfig.Options() {
		if o, ok := opt.(PubkeyAuthOption); ok {
			if len(agentKeys) == 0 {
				log.Warn().Msgf("no SSH key found in agent")
				return nil, nil
			}
			var methods []auth.ClientAuthMethod
			for _, filename := range o.Filenames() {
				keyBytes, err := os.ReadFile(util.ExpandTildeWithHomeDir(filename))
				if err != nil {
					log.Error().Msgf("could not read public key located at %s: %s", filename, err)
					return nil, err
				}

				pubkey, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
				if err != nil {
					// only debug level since OpenSSH's config uses IdentityFile for both pubkeys and privkeys
					log.Debug().Msgf("could not parse public key located at %s: %s", filename, err)
				} else {
					for _, agentKey := range agentKeys {
						if bytes.Equal(agentKey.Marshal(), pubkey.Marshal()) {
							log.Debug().Msgf("key %s found in agent", filename)
							methods = append(methods, NewPubkeyAuthMethod(agentKey))
							break
						}
					}
				}
			}
			return methods, nil
		}
	}
	return nil, nil
}
