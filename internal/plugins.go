package internal

import (
	"sync"

	"github.com/francoismichel/ssh3/auth"
	"github.com/francoismichel/ssh3/util"
	"github.com/rs/zerolog/log"
)

type pluginsRegistry[T any] struct {
	registrationsOpen bool
	registerMutex     sync.RWMutex
	plugins           map[string]T
}

func (r *pluginsRegistry[T]) registerPlugin(name string, plugin T) error {
	if r == nil || r.plugins == nil {
		panic("plugin registry is nil")
	}
	r.registerMutex.Lock()
	defer r.registerMutex.Unlock()
	if !r.registrationsOpen {
		return util.ClosedPluginsRegistry{}
	}
	if _, dup := r.plugins[name]; dup {
		panic("registerPlugin called twice for same auth plugin name " + name)
	}
	r.plugins[name] = plugin
	log.Info().Msgf("plugin %s successfully registered", name)
	return nil
}

// Closes the registry. This function should not be exported outside the scope of the module
// to avoid plugins closing the registry.
func (r *pluginsRegistry[T]) closeRegistry() {
	r.registerMutex.Lock()
	defer r.registerMutex.Unlock()
	serverRegistry.registrationsOpen = false
}

var (
	serverRegistry = newPluginsRegistry[auth.ServerAuthPlugin]()
	clientRegistry = newPluginsRegistry[auth.ClientAuthPlugin]()
)

func RegisterServerAuthPlugin(name string, plugin auth.ServerAuthPlugin) error {
	return serverRegistry.registerPlugin(name, plugin)
}

func RegisterClientAuthPlugin(name string, plugin auth.ClientAuthPlugin) error {
	return clientRegistry.registerPlugin(name, plugin)
}

func CloseClientPluginsRegistry() {
	clientRegistry.closeRegistry()
}
func CloseServerPluginsRegistry() {
	serverRegistry.closeRegistry()
}

func newPluginsRegistry[T any]() *pluginsRegistry[T] {
	return &pluginsRegistry[T]{registrationsOpen: true, plugins: make(map[string]T)}
}

func FindIdentitiesFromAuthorizedIdentityString(username string, authorizedIdentityString string) (identities []auth.RequestIdentityVerifier) {
	serverRegistry.registerMutex.RLock()
	for name, parseIdentityPlugin := range serverRegistry.plugins {
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
