package client

import (
	"fmt"
	"net"
)


type Options struct {
	username 	string
	hostname	string
	port		int
	urlPath		string
	authMethods []interface{}
}

func NewOptions(username string, hostname string, port int, urlPath string, authMethods []interface{}) (*Options, error) {
	if urlPath[0] != '/' {
		urlPath = "/" + urlPath
	}
	return &Options{
		username: username,
		hostname: hostname,
		port: port,
		urlPath: urlPath,
		authMethods: authMethods,
	}, nil
}

func (o *Options) Username() string {
	return o.username
}

func (o *Options) Hostname() string {
	return o.hostname
}

// Returns the pair hostname:port in a valid URL format.
// This means that an IPv6 will be written inside square brackets [].
// examples: "127.0.0.1:443", "example.org:1234", "[::1]:22""
func (o *Options) URLHostnamePort() string {
	hostnameIsAnIP := net.ParseIP(o.hostname) != nil
	if hostnameIsAnIP {
		ip := net.ParseIP(o.hostname)
		if ip.To4() == nil && ip.To16() != nil {
			// enforce the square-bracketed notation for ipv6 UDP addresses
			return fmt.Sprintf("[%s]:%d", o.hostname, o.port)
		}
	}
	return fmt.Sprintf("%s:%d", o.hostname, o.port)
}

func (o *Options) Port() int {
	return o.port
}
func (o *Options) UrlPath() string {
	return o.urlPath
}

// Returns the canonical host representation used by SSH3.
// The format is <urlhostnameport><path>
// <urlhostnameport> is the host:port pair in the format returned by
// URLHostnamePort()
// <path> is the URL path, it always starts with a "/", it is therefore never empty.
func (o *Options) CaonicalHostFormat() string {
	return fmt.Sprintf("%s:%d%s", o.hostname, o.port, o.urlPath)
}

func (o *Options) AuthMethods() []interface{} {
	return o.authMethods
}
