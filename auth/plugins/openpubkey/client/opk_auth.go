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
	plugins.RegisterClientAuthPlugin("openpubkey_auth", plugin)
}

const OPENPUBKEY_OPTION_NAME = "github.com/openpubkey/ssh3-openpubkey_auth"

// Implements client-side OpenPubkey authentication
type OpenPubkeyAuthOption struct {
	issuer string
}

// Issuer returns the OpenID Provider issuer URI specified by the user
func (o *OpenPubkeyAuthOption) Issuer() string {
	return o.issuer
}

// OpenPubkeyOptionParser handles SSH3 command line arguments relevant to OpenPubkey.
// An example command: `./ssh3 -openpubkey https://accounts.google.com user1234@example.com:443/ssh3-term`
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
	return &OpenPubkeyAuthOption{
		issuer: values[0],
	}, nil
}

// Usage implements config.CLIOptionParser.
func (*OpenPubkeyOptionParser) Usage() string {
	return "OpenID Provider to use"
}

var _ config.CLIOptionParser = &OpenPubkeyOptionParser{}

// openpubkeyPluginFunc is set as the PluginFunc for the plugin in init(). Its purpose
// is to:
// 1. read the config/options set by the SSH3 client,
// 2. determine if OpenPubkey auth would be appropriate given the config/options specified,
// 3. and if so, return the OpenPubkeyAuthMethod for the specified options/config.
var openpubkeyPluginFunc auth.GetClientAuthMethodsFunc = func(request *http.Request,
	sshAgent agent.ExtendedAgent, clientConfig *config.Config,
	roundTripper *http3.RoundTripper) ([]auth.ClientAuthMethod, error) {
	for _, opt := range clientConfig.Options() {
		if o, ok := opt.(*OpenPubkeyAuthOption); ok {
			switch o.Issuer() {
			// We only support Google
			case "https://accounts.google.com":
				providerOpts := providers.GetDefaultGoogleOpOptions()
				providerOpts.GQSign = false
				provider := providers.NewGoogleOpWithOptions(providerOpts)
				methods := []auth.ClientAuthMethod{
					&OpenPubkeyAuthMethod{
						provider: provider,
					}}
				return methods, nil
			// Add new OpenID Provider support here
			default:
				log.Error().Msgf("openID Provider is not supported by OpenPubkey: issuer=%s", o.Issuer())
				return nil, nil
			}
		}
	}
	return nil, nil
}

// OpenPubkeyAuthMethod implements auth.ClientAuthMethod.
type OpenPubkeyAuthMethod struct {
	provider providers.OpenIdProvider
}

// PrepareRequestForAuth implements auth.ClientAuthMethod.
// This function performs the client side of the OpenPubkey authentication.
func (o *OpenPubkeyAuthMethod) PrepareRequestForAuth(request *http.Request,
	sshAgent agent.ExtendedAgent, roundTripper *http3.RoundTripper,
	username string, conversation *ssh3.Conversation) error {
	opkClient, err := client.New(o.provider)
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
