// Package renderer implements ByteForge's output renderer registry.
//
// Renderers format the bytes produced by a codec or cipher. They never change
// the underlying data semantics and never add loader or execution code.
package renderer

import (
	"sort"
	"sync"

	"github.com/zoro/byteforge/internal/registry"
)

var (
	mu     sync.RWMutex
	byName = map[string]registry.Renderer{}
)

// Register adds a renderer. Duplicate names are a programming error.
func Register(r registry.Renderer) {
	mu.Lock()
	defer mu.Unlock()
	name := r.Info().Name
	if _, exists := byName[name]; exists {
		panic("renderer: duplicate registration for " + name)
	}
	byName[name] = r
}

// Get returns a renderer by identifier.
func Get(name string) (registry.Renderer, bool) {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := byName[name]
	return r, ok
}

// All returns registered renderers sorted by name.
func All() []registry.Renderer {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]registry.Renderer, 0, len(byName))
	for _, r := range byName {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}

// Names returns renderer identifiers sorted by name.
func Names() []string {
	all := All()
	out := make([]string, len(all))
	for i, r := range all {
		out[i] = r.Info().Name
	}
	return out
}
