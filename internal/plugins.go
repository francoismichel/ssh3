package internal

import (
	"sync"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/util"
	"github.com/rs/zerolog/log"
)

type serverPluginsRegistry struct {
	registrationsOpen bool
	serverAuthPlugins map[string]auth.ServerAuthPlugin
}

var (
	serverPluginsMutex sync.RWMutex
	serverRegistry     = &serverPluginsRegistry{registrationsOpen: true, serverAuthPlugins: make(map[string]auth.ServerAuthPlugin)}
)

// Registers a new server-side auth plugin
func RegisterServerAuthPlugin(name string, plugin auth.ServerAuthPlugin) error {
	serverPluginsMutex.Lock()
	defer serverPluginsMutex.Unlock()
	if !serverRegistry.registrationsOpen {
		return util.ClosedPluginsRegistry{}
	}
	if plugin == nil {
		panic("plugin registry is nil")
	}
	if _, dup := serverRegistry.serverAuthPlugins[name]; dup {
		panic("RegisterServerIdentity called twice for same auth plugin name " + name)
	}
	serverRegistry.serverAuthPlugins[name] = plugin
	log.Info().Msgf("plugin %s successfully registered", name)
	return nil
}

func FindIdentitiesFromAuthorizedIdentityString(username string, authorizedIdentityString string) (identities []auth.RequestIdentityVerifier) {
	serverPluginsMutex.RLock()
	for name, parseIdentityPlugin := range serverRegistry.serverAuthPlugins {
		identity, err := parseIdentityPlugin(username, authorizedIdentityString)
		if err != nil {
			log.Error().Msgf("error when executing plugin %s", name)
		} else if identity != nil {
			log.Debug().Msgf("found an identity for plugin %s", name)
			identities = append(identities, identity)
		}
	}
	return identities
}

// Closes the registry. This function should not be exported outside the scope of the module
// to avoid plugins closing the registry.
func CloseRegistry() {
	serverPluginsMutex.Lock()
	defer serverPluginsMutex.Unlock()
	serverRegistry.registrationsOpen = false
}
