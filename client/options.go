package client

import (
	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
)


type Options struct {
	knownHosts ssh3.KnownHosts
	oidcConfig auth.OIDCIssuerConfig
	authMethods []interface{}
}

func NewOptions(knownHosts ssh3.KnownHosts, oidcConfig auth.OIDCIssuerConfig, authMethods []interface{}) (*Options, error) {
	return &Options{
		knownHosts: knownHosts,
		authMethods: authMethods,
		oidcConfig: oidcConfig,
	}, nil
}