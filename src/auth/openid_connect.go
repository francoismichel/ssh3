package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func Connect(ctx context.Context, clientID string, issuerUrl string) error {
	provider, err := oidc.NewProvider(ctx, issuerUrl)
	if err != nil {
		return err
	} 	

	providerEndpoint := provider.Endpoint()

		// Configure an OpenID Connect aware OAuth2 client.
	oauthConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "",
		RedirectURL:  "",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: providerEndpoint,

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	
	randomSecretUrl := [64]byte{}
	_, err = rand.Read(randomSecretUrl[:])
	if err != nil {
		return err
	}
	url.QueryEscape(string(randomSecretUrl[:]))

 	listener, err := net.Listen("tcp", ":0")
 	if err != nil {
		 panic(err)
	}
	 
	path := fmt.Sprintf("/ssh/%s", randomSecretUrl)
	mux := http.NewServeMux()
	mux.Handle(path, getOAuth2Callback(ctx, provider, clientID, &oauthConfig))
	listeningPort := listener.Addr().(*net.TCPAddr).Port
	server := http.Server{ Handler: mux }
	go server.Serve(listener)
	 
	secretUrl := fmt.Sprintf("http://localhost:%d%s", listeningPort, path)

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
    params.Add("scope", "openid")
    params.Add("client_id", clientID)

	browserURL.RawQuery = params.Encode()
	fmt.Println(browserURL)

	args = append(args, browserURL.String())
	fmt.Printf("spawning browser at %s\n", browserURL)
	command := exec.Command(cmd, args...)
	err = command.Start()
	if err != nil {
		return err
	}
	command.Wait()
	 // todo: trigger a browser on localhost on the listeningPort and fetch the token, and then close the http server
	return nil
}

func getOAuth2Callback(ctx context.Context, provider *oidc.Provider, clientID string, oauth2Config *oauth2.Config) http.HandlerFunc {
	
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return func(w http.ResponseWriter, r *http.Request) {
		// Verify state and errors.
		fmt.Println("received request:", r)
		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			// handle error
		}
	
		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			// handle missing token
		}
	
		// Parse and verify ID Token payload.
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			// handle error
		}
	
		// Extract custom claims
		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			// TODO: handle error
		}
	}
}
