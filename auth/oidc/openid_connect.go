package oidc

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

type OIDCIssuerConfig = []*OIDCConfig
type OIDCConfig struct {
	IssuerUrl    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

/*
 *	Gets an OpenID Connect authorization token from the authorization provider (issuer).
 *  It firsts discuvers the authorization endppoint from the issuerURL. Then, it
 *  opens a browser window towards the authorization endpoint. A local webserver is temporarily
 *  started at a random port to retrieve the issued authorization token.
 *	This token is then returned as an http url-encoded string.
 */
func Connect(ctx context.Context, oidcConfig *OIDCConfig, issuerURL string, doPKCE bool) (rawIDTokey string, err error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return "", err
	}

	providerEndpoint := provider.Endpoint()

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}


	path := "/ssh"
	listeningPort := listener.Addr().(*net.TCPAddr).Port

	secretUrl := fmt.Sprintf("http://localhost:%d%s", listeningPort, path)

	// Configure an OpenID Connect aware OAuth2 client.
	oauthConfig := oauth2.Config{
		ClientID:     oidcConfig.ClientID,
		ClientSecret: oidcConfig.ClientSecret,
		RedirectURL:  secretUrl,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: providerEndpoint,

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{"openid email"},
	}

	challengeVerifierBytes := [64]byte{}
	_, err = rand.Read(challengeVerifierBytes[:])
	if err != nil {
		return "", fmt.Errorf("error when generating random verifier: %s", err.Error())
	}

	verifier := oauth2.GenerateVerifier()

	tokenChannel := make(chan string)
	mux := http.NewServeMux()
	mux.Handle(path, getOAuth2Callback(ctx, provider, oidcConfig.ClientID, &oauthConfig, tokenChannel, verifier, doPKCE))
	server := http.Server{Handler: mux}
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

	options := []oauth2.AuthCodeOption{}
	if doPKCE {
		options = append(options, oauth2.S256ChallengeOption(verifier))
	}

	authCodeURL := oauthConfig.AuthCodeURL("state", options...)

	args = append(args, authCodeURL)
	log.Debug().Msgf("spawning browser at %s\n", authCodeURL)
	command := exec.Command(cmd, args...)
	err = command.Start()
	if err != nil {
		return "", err
	}

	rawIDToken := <-tokenChannel
	log.Debug().Msgf("got token: %s", rawIDToken)
	server.Close()
	// todo: trigger a browser on localhost on the listeningPort and fetch the token, and then close the http server
	return rawIDToken, nil
}

func getOAuth2Callback(ctx context.Context, provider *oidc.Provider, clientID string, oauth2Config *oauth2.Config,
	tokenChannel chan string, challengeVerifier string, doPKCE bool) http.HandlerFunc {

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return func(w http.ResponseWriter, r *http.Request) {
		defer w.(http.Flusher).Flush()
		// Verify state and errors.

		options := []oauth2.AuthCodeOption{}
		if doPKCE {
			options = append(options, oauth2.VerifierOption(challengeVerifier))
		}
		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"), options...)
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

		w.Write([]byte("you can now close this tab")) // status 200 is implicit
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
