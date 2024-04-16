package plugins

import (
	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/internal"
)

// Registers a new server-side auth plugin
func RegisterServerAuthPlugin(name string, plugin auth.ServerAuthPlugin) error {
	return internal.RegisterServerAuthPlugin(name, plugin)
}

func RegisterClientAuthPlugin(name string, plugin auth.ClientAuthPlugin) error {
	return internal.RegisterClientAuthPlugin(name, plugin)
}
