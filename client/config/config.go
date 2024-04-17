package options

import (
	"fmt"
	"net"
)

type OptionName string

type Config struct {
	username string
	hostname string
	port     int
	urlPath  string

	options     map[OptionName]Option
	authMethods []interface{} // soon deprecated or heaviy modified
}

func NewConfig(username string, hostname string, port int, urlPath string, authMethods []interface{}, options map[OptionName]Option) (*Config, error) {
	if len(urlPath) == 0 || urlPath[0] != '/' {
		urlPath = "/" + urlPath
	}
	return &Config{
		username:    username,
		hostname:    hostname,
		port:        port,
		urlPath:     urlPath,
		authMethods: authMethods,
		options:     options,
	}, nil
}

func (o *Config) Username() string {
	return o.username
}

func (o *Config) Hostname() string {
	return o.hostname
}

// Returns the pair hostname:port in a valid URL format.
// This means that an IPv6 will be written inside square brackets [].
// examples: "127.0.0.1:443", "example.org:1234", "[::1]:22""
func (o *Config) URLHostnamePort() string {
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

func (o *Config) Port() int {
	return o.port
}
func (o *Config) UrlPath() string {
	return o.urlPath
}

// Returns the canonical host representation used by SSH3.
// The format is <urlhostnameport><path>
// <urlhostnameport> is the host:port pair in the format returned by
// URLHostnamePort()
// <path> is the URL path, it always starts with a "/", it is therefore never empty.
func (o *Config) CanonicalHostFormat() string {
	return fmt.Sprintf("%s:%d%s", o.hostname, o.port, o.urlPath)
}

func (o *Config) AuthMethods() []interface{} {
	return o.authMethods
}

func (o *Config) Options() map[OptionName]Option {
	return o.options
}

// Option defnes a generic client option that can be manipulated by the client
// and by different auth plugins. Plugins can define their own option types
type Option any

// StringOptions is a client option whose value is a string
type StringOption interface {
	Option
	Value() string
}

// OptionParser allows parsing an client config option from a string.
type OptionParser interface {
	// returns the option config keyword
	// This keyword is used when parsing the SSH config.
	OptionConfigName() string

	// returns the Option[T] represented by this CLI argument.
	// Option() will always be called *after* having parsed the CLI args using flag.Parse()
	Parse(string) (Option, error)
}

// CLIOptionParser defines a parser that can be hooked in the CLI flags

type CLIOptionParser interface {
	OptionParser
	FlagName() string
	Usage() string
	// returns whether it should be considered as a boolean flag (parsed using flag.Bool(), with no flag value)
	// or as a flag with a value. If IsBoolFlag returns true, the Parse() method will be called with "yes" or "no"
	// depending of the boolean value of the arg
	IsBoolFlag() bool
}
