package client

import (
	"crypto/x509"

	"github.com/francoismichel/ssh3"
)


type Options struct {
	verifyHostCertificate bool
	knownHosts map[string][]*x509.Certificate
	authMethods []interface{}
}
