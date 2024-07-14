package plugins

import (
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/internal"
)

// Each new plugin package must define an init() method (see https://go.dev/doc/effective_go#init)
// in which they register one or more authentication plugins by calling either RegisterServerAuthPlugin()
// for server-side auth plugins or RegisterClientAuthPlugin() for client-side auth plugins.

// Registers a new server-side auth plugin
func RegisterServerAuthPlugin(name string, plugin auth.ServerAuthPlugin) error {
	return internal.RegisterServerAuthPlugin(name, plugin)
}

// Registers a new client-side auth plugin
func RegisterClientAuthPlugin(name string, plugin auth.ClientAuthPlugin) error {
	return internal.RegisterClientAuthPlugin(name, plugin)
}
