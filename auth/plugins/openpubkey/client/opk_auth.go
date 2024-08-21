package openpubkey_authentication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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
	issuer string
}

func (o *OpenPubkeyAuthOption) Issuer() string {
	return o.issuer
}

type OpenPubkeyOptionParser struct{}

// FlagName implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) FlagName() string {
	return "openpubkey"
}

// IsBoolFlag implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) IsBoolFlag() bool {
	return false
}

// OptionConfigName implements config.OptionParser.
func (*OpenPubkeyOptionParser) OptionConfigName() string {
	return "OpenPubkey"
}

// Parse implements config.OptionParser.
func (*OpenPubkeyOptionParser) Parse(values []string) (config.Option, error) {
	fmt.Println("OpenPubkeyOptionParser.Parse", values)

	return &OpenPubkeyAuthOption{
		issuer: values[0],
	}, nil
}

// Usage implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) Usage() string {
	return "OpenID Provider to use"
}

var _ config.CLIOptionParser = &OpenPubkeyOptionParser{}

var openpubkeyPluginFunc auth.GetClientAuthMethodsFunc = func(request *http.Request, sshAgent agent.ExtendedAgent, clientConfig *config.Config, roundTripper *http3.RoundTripper) ([]auth.ClientAuthMethod, error) {
	for _, opt := range clientConfig.Options() {
		if o, ok := opt.(*OpenPubkeyAuthOption); ok {
			// We currently only support Google right now
			if o.Issuer() == "https://accounts.google.com" {
				opOptions := providers.GetDefaultGoogleOpOptions()
				opOptions.GQSign = false
				op := providers.NewGoogleOpWithOptions(opOptions)

				methods := []auth.ClientAuthMethod{
					&OpenPubkeyAuthMethod{
						Issuer:   o.Issuer(),
						Provider: op,
					}}
				return methods, nil

			} else {
				log.Error().Msgf("OpenID Provider %s not supported", o.Issuer())
			}
		}
	}

	return nil, nil
}

type OpenPubkeyAuthMethod struct {
	Issuer   string
	Provider providers.OpenIdProvider
}

func (o *OpenPubkeyAuthMethod) PrepareRequestForAuth(request *http.Request, sshAgent agent.ExtendedAgent, roundTripper *http3.RoundTripper, username string, conversation *ssh3.Conversation) error {
	op := o.Provider
	opkClient, err := client.New(op)
	if err != nil {
		return err
	}
	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return err
	}
	pktCom, err := pkt.Compact()
	if err != nil {
		return err
	}
	convID := conversation.ConversationID()
	b64ConvID := base64.StdEncoding.EncodeToString(convID[:])
	claims := jwt.MapClaims{
		"iss":       username,
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
		"sub":       "ssh3",
		"aud":       "unused",
		"client_id": fmt.Sprintf("ssh3-%s", username),
		"jti":       b64ConvID,
	}
	msg, err := json.Marshal(claims)
	if err != nil {
		return err
	}

	osm, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s#%s", osm, pktCom))
	return nil
}
