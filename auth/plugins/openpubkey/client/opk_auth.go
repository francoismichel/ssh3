package openpubkey_authentication

import (
	"context"
	"fmt"
	"net/http"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/auth/plugins"
	"github.com/francoismichel/ssh3/client/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh/agent"
)

func init() {
	plugin := auth.ClientAuthPlugin{
		PluginOptions: map[config.OptionName]config.OptionParser{OPENPUBKEY_OPTION_NAME: &OpenPubkeyOptionParser{}},
		PluginFunc:    openpubkeyPluginFunc,
	}
	log.Info().Msgf("Registering OpenPubkey")

	plugins.RegisterClientAuthPlugin("openpubkey_auth", plugin)
}

const OPENPUBKEY_OPTION_NAME = "github.com/openpubkey/ssh3-openpubkey_auth"

// impements client-side pubkey-based authentication

type OpenPubkeyAuthOption struct {
	filenames []string
}

// impements client-side pubkey-based authentication

func (o *OpenPubkeyAuthOption) Filenames() []string {
	return o.filenames
}

type OpenPubkeyOptionParser struct{}

// FlagName implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) FlagName() string {
	return "opk"
}

// IsBoolFlag implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) IsBoolFlag() bool {
	return false
}

// OptionConfigName implements config.OptionParser.
func (*OpenPubkeyOptionParser) OptionConfigName() string {
	return "IdentityFile"
}

// Parse implements config.OptionParser.
func (*OpenPubkeyOptionParser) Parse(values []string) (config.Option, error) {
	return &OpenPubkeyAuthOption{
		filenames: values,
	}, nil
}

// Usage implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) Usage() string {
	return "private key file"
}

var _ config.CLIOptionParser = &OpenPubkeyOptionParser{}

var openpubkeyPluginFunc auth.GetClientAuthMethodsFunc = func(request *http.Request, sshAgent agent.ExtendedAgent, clientConfig *config.Config, roundTripper *http3.RoundTripper) ([]auth.ClientAuthMethod, error) {
	// for _, opt := range clientConfig.Options() {
	// 	if o, ok := opt.(*OpenPubkeyAuthOption); ok {
	// 		var methods []auth.ClientAuthMethod
	// 		for _, filename := range o.Filenames() {
	// 			methods = append(methods, &PrivkeyFileAuthMethod{filename: filename})
	// 		}
	// 		return methods, nil
	// 	}
	// }
	// return nil, nil
	methods := []auth.ClientAuthMethod{&OpenPubkeyAuthMethod{}}
	return methods, nil
}

type OpenPubkeyAuthMethod struct {
}

func (*OpenPubkeyAuthMethod) PrepareRequestForAuth(request *http.Request, sshAgent agent.ExtendedAgent, roundTripper *http3.RoundTripper, username string, conversation *ssh3.Conversation) error {
	opOptions := providers.GetDefaultGoogleOpOptions()
	opOptions.GQSign = false
	op := providers.NewGoogleOpWithOptions(opOptions)
	opkClient, err := client.New(op)
	if err != nil {
		return err
	}

	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return err
	}

	jwtBearerKey := opkClient.GetSigner()
	signingMethod := jwt.SigningMethodES256
	pktCom, err := pkt.Compact()
	if err != nil {
		return err
	}

	kid, err := pkt.Hash()
	if err != nil {
		return err
	}
	bearerToken, err := ssh3.BuildOPKBearerToken(signingMethod, jwtBearerKey, username, conversation, string(pktCom), kid)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	return nil
}
