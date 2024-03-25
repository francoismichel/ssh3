package internal

import (
	"sync"

	"github.com/francoismichel/ssh3/server_auth"
	. "github.com/francoismichel/ssh3/util"
)

type serverPluginsRegistry struct {
	registrationsOpen 	   bool
	serverPluginIdentities map[string]server_auth.Identity
}

var (
	serverPluginsMutex sync.RWMutex
	serverRegistry = &serverPluginsRegistry{ registrationsOpen: true, serverPluginIdentities: make(map[string]server_auth.Identity) }
)

// Registers a new server-side auth plugin
func RegisterServerIdentity(name string, identity server_auth.Identity) error {
	serverPluginsMutex.Lock()
	defer serverPluginsMutex.Unlock()
	if !serverRegistry.registrationsOpen {
		return ClosedPluginsRegistry{}
	}
	if identity == nil {
		panic("plugin registry is nil")
	}
	if _, dup := serverRegistry.serverPluginIdentities[name]; dup {
		panic("RegisterServerIdentity called twice for same auth plugin name " + name)
	}
	serverRegistry.serverPluginIdentities[name] = identity
	return nil
}

// Closes the registry. This function should not be exported outside the scope of the module
// to avoid plugins closing the registry.
func CloseRegistry() {
	serverPluginsMutex.Lock()
	defer serverPluginsMutex.Unlock()
	serverRegistry.registrationsOpen = false
}