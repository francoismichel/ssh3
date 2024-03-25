package plugins

import (
	"github.com/francoismichel/ssh3/internal"
	"github.com/francoismichel/ssh3/server_auth"
)

// Registers a new server-side auth plugin
func RegisterServerIdentity(name string, identity server_auth.Identity) error {
	return internal.RegisterServerIdentity(name, identity)
}
