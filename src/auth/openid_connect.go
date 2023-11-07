package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

/*
 *	Gets an OpenID Connect authorization token from the authorization provider (issuer).
 *  It firsts discuvers the authorization endppoint from the issuerURL. Then, it
 *  opens a browser window towards the authorization endpoint. A local webserver is temporarily
 *  started at a random port to retrieve the issued authorization token.
 *	This token is then returned as an http url-encoded string.
*/
func Connect(ctx context.Context, clientID string, clientSecret string, issuerURL string) (rawIDTokey string, err error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", err
	} 	

	providerEndpoint := provider.Endpoint()
	
	randomSecretUrlBytes := [64]byte{}
	_, err = rand.Read(randomSecretUrlBytes[:])
	if err != nil {
		return "", err
	}

	randomSecretUrl := hex.EncodeToString(randomSecretUrlBytes[:])

 	listener, err := net.Listen("tcp", ":0")
 	if err != nil {
		 panic(err)	
	}
	 
	path := fmt.Sprintf("/ssh/%s", randomSecretUrl)
	listeningPort := listener.Addr().(*net.TCPAddr).Port
	 
	secretUrl := fmt.Sprintf("http://localhost:%d%s", listeningPort, path)

		// Configure an OpenID Connect aware OAuth2 client.
	oauthConfig := oauth2.Config{
		ClientID:     clientID,
		RedirectURL:  secretUrl,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: providerEndpoint,

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email"},
	}

	tokenChannel := make(chan string)
	mux := http.NewServeMux()
	mux.Handle(path, getOAuth2Callback(ctx, provider, clientID, &oauthConfig, tokenChannel))
	server := http.Server{ Handler: mux }
	go server.Serve(listener)
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
	 	cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}


    browserURL, _ := url.Parse(providerEndpoint.AuthURL)
    params := url.Values{}
    params.Add("redirect_uri", secretUrl)
    params.Add("prompt", "select_account")
    params.Add("response_type", "code")
    params.Add("scope", "openid email")
    params.Add("client_id", clientID)

	browserURL.RawQuery = params.Encode()

	args = append(args, browserURL.String())
	log.Debug().Msgf("spawning browser at %s\n", browserURL)
	command := exec.Command(cmd, args...)
	err = command.Start()
	if err != nil {
		return "", err
	}
	command.Wait()

	
	rawIDToken := <-tokenChannel
	log.Debug().Msgf("got token: %s", rawIDToken)
	server.Close()
	 // todo: trigger a browser on localhost on the listeningPort and fetch the token, and then close the http server
	return rawIDToken, nil
}

func getOAuth2Callback(ctx context.Context, provider *oidc.Provider, clientID string, oauth2Config *oauth2.Config, tokenChannel chan string) http.HandlerFunc {

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return func(w http.ResponseWriter, r *http.Request) {
		// Verify state and errors.

		challengeVerifierBytes := [64]byte{}
		_, err := rand.Read(challengeVerifierBytes[:])
		if err != nil {
			log.Error().Msgf("error when generating random verifier: %s", err.Error())
			return
		}
		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.S256ChallengeOption(string(challengeVerifierBytes[:])))
		if err != nil {
			log.Error().Msgf("error when parsing oauth token: %s", err.Error())
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Error().Msgf("missing id token in the retrieved oauth2 token")
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Error().Msgf("error when verifying oauth token: %s", err.Error())
			return
		}

		// Extract custom claims
		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			log.Error().Msgf("error when parsing the oauth token claims: %s", err.Error())
			return
		}
		tokenChannel <- rawIDToken
	}
}

func VerifyRawToken(ctx context.Context, clientID string, issuerURL string, rawIDToken string) (*oidc.IDToken, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	} 	


	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(ctx, rawIDToken)
	// TODO: nonce validation ? Is id needed here ?

	return idToken, err
}
