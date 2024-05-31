package client_pubkey_authentication

import (
	"bytes"
	"crypto"
	"fmt"
	"net/http"
	"os"
	"syscall"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/client/config"
	"github.com/francoismichel/ssh3/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

func init() {
	plugin := auth.ClientAuthPlugin{
		PluginOptions: map[config.OptionName]config.OptionParser{PRIVKEY_OPTION_NAME: &PrivkeyOptionParser{}},
		PluginFunc:    privkeyPluginFunc,
	}
	plugins.RegisterClientAuthPlugin("privkey_auth", plugin)
}

const PRIVKEY_OPTION_NAME = "github.com/francoismichel/ssh3-privkey_auth"

// implements client-side pubkey-based authentication

type PrivkeyAuthOption struct {
	filenames []string
}

func (o *PrivkeyAuthOption) Filenames() []string {
	return o.filenames
}

type PrivkeyOptionParser struct{}

// FlagName implements config.CLIOptionParser.
func (*PrivkeyOptionParser) FlagName() string {
	return "privkey"
}

// IsBoolFlag implements config.CLIOptionParser.
func (*PrivkeyOptionParser) IsBoolFlag() bool {
	return false
}

// OptionConfigName implements config.OptionParser.
func (*PrivkeyOptionParser) OptionConfigName() string {
	return "IdentityFile"
}

// Parse implements config.OptionParser.
func (*PrivkeyOptionParser) Parse(values []string) (config.Option, error) {
	return &PrivkeyAuthOption{
		filenames: values,
	}, nil
}

// Usage implements config.CLIOptionParser.
func (*PrivkeyOptionParser) Usage() string {
	return "private key file"
}

var _ config.CLIOptionParser = &PrivkeyOptionParser{}

type PrivkeyFileAuthMethod struct {
	filename   string
	passphrase *string
}

func NewPrivkeyFileAuthMethod(filename string) *PrivkeyFileAuthMethod {
	return &PrivkeyFileAuthMethod{
		filename: util.ExpandTildeWithHomeDir(filename),
	}
}

func (m *PrivkeyFileAuthMethod) Filename() string {
	return m.filename
}

func (m *PrivkeyFileAuthMethod) getCryptoMaterial() (crypto.Signer, jwt.SigningMethod, error) {

	keyBytes, err := os.ReadFile(m.filename)
	if err != nil {
		return nil, nil, err
	}
	var cryptoSigner crypto.Signer
	var signer interface{}

	var ok bool
	if m.passphrase == nil {
		signer, err = ssh.ParseRawPrivateKey(keyBytes)
	} else {
		signer, err = ssh.ParseRawPrivateKeyWithPassphrase(keyBytes, []byte(*m.passphrase))
	}
	if err != nil {
		return nil, nil, err
	}
	// transform the abstract type into a crypto.Signer that can be used with the jwt lib
	if cryptoSigner, ok = signer.(crypto.Signer); !ok {
		return nil, nil, fmt.Errorf("the provided key file does not result in a crypto.Signer type")
	}
	signingMethod, err := util.JWTSigningMethodFromCryptoPubkey(cryptoSigner.Public())
	if err != nil {
		return nil, nil, err
	}
	return cryptoSigner, signingMethod, nil
}

// PrepareRequestForAuth implements auth.ClientAuthMethod.
func (m *PrivkeyFileAuthMethod) PrepareRequestForAuth(request *http.Request, sshAgent agent.ExtendedAgent, roundTripper *http3.RoundTripper, username string, conversation *ssh3.Conversation) error {
	log.Debug().Msgf("try file-based privkey auth using file %s", m.Filename())
	var jwtBearerKey any
	jwtBearerKey, signingMethod, err := m.getCryptoMaterial()
	// could not identify without passphrase, try agent authentication by using the key's public key
	if passphraseErr, ok := err.(*ssh.PassphraseMissingError); ok {
		// the pubkey may be contained in the privkey file
		pubkey := passphraseErr.PublicKey
		if pubkey == nil {
			// if it is not the case, try to find a .pub equivalent, like OpenSSH does
			pubkeyBytes, err := os.ReadFile(fmt.Sprintf("%s.pub", m.Filename()))
			if err == nil {
				filePubkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
				if err == nil {
					pubkey = filePubkey
				}
			}
		}
		var agentKeys []*agent.Key
		if sshAgent != nil {
			agentKeys, err = sshAgent.List()
			if err != nil {
				log.Warn().Msgf("error when listing SSH agent keys: %s", err)
				err = nil
				agentKeys = nil
			}
		}
		// now, try to see of the agent manages this key
		foundAgentKey := false
		if pubkey != nil {
			for _, agentKey := range agentKeys {
				if bytes.Equal(agentKey.Marshal(), pubkey.Marshal()) {
					log.Debug().Msgf("found key in agent: %s, switch to agent-based pubkey auth", agentKey)
					pubkeyAuthMethod := NewPubkeyAuthMethod(agentKey)
					// handle that using the public key auth plugin
					return pubkeyAuthMethod.PrepareRequestForAuth(request, sshAgent, roundTripper, username, conversation)
				}
			}
		}

		// key not handled by agent, let's try to decrypt it ourselves
		if !foundAgentKey {
			fmt.Printf("passphrase for private key stored in %s:", m.Filename())
			var passphraseBytes []byte
			passphraseBytes, err = term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				log.Error().Msgf("could not get passphrase: %s", err)
				return err
			}
			passphrase := string(passphraseBytes)
			m.passphrase = &passphrase
			jwtBearerKey, signingMethod, err = m.getCryptoMaterial()
			if err != nil {
				log.Error().Msgf("could not load private key: %s", err)
				return err
			}
		}
	} else if err != nil {
		log.Warn().Msgf("Could not load private key: %s", err)
	}

	bearerToken, err := ssh3.BuildJWTBearerToken(signingMethod, jwtBearerKey, username, conversation)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))
	return nil
}

var _ auth.ClientAuthMethod = &PrivkeyFileAuthMethod{}

var privkeyPluginFunc auth.GetClientAuthMethodsFunc = func(request *http.Request, sshAgent agent.ExtendedAgent, clientConfig *config.Config, roundTripper *http3.RoundTripper) ([]auth.ClientAuthMethod, error) {
	for _, opt := range clientConfig.Options() {
		if o, ok := opt.(*PrivkeyAuthOption); ok {
			var methods []auth.ClientAuthMethod
			for _, filename := range o.Filenames() {
				methods = append(methods, &PrivkeyFileAuthMethod{filename: filename})
			}
			return methods, nil
		}
	}
	return nil, nil
}
