package client

import (
	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/auth"
)


type Options struct {
	verifyHostCertificate bool
	knownHosts ssh3.KnownHosts
	oidcConfig auth.OIDCIssuerConfig
	authMethods []interface{}
}

func NewOptions(verifyHostCertificate bool, knownHosts ssh3.KnownHosts, oidcConfig auth.OIDCIssuerConfig, authMethods []interface{}) (*Options, error) {
	return &Options{
		verifyHostCertificate: verifyHostCertificate,
		knownHosts: knownHosts,
		authMethods: authMethods,
		oidcConfig: oidcConfig,
	}, nil
}