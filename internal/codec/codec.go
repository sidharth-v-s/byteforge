// Package codec implements ByteForge's representation codec registry.
//
// Codecs are reversible byte-to-byte (or byte-to-text) conversions. Typed
// codecs such as mac, ipv4, ipv6, and uuid intentionally reject inputs whose
// length does not match the represented type; they are not general-purpose
// encodings for arbitrary payloads.
package codec

import (
	"sort"
	"sync"

	"github.com/zoro/byteforge/internal/registry"
)

var (
	mu     sync.RWMutex
	byName = map[string]registry.Codec{}
)

// Register adds a codec. Registering a duplicate name is a programming error.
func Register(c registry.Codec) {
	mu.Lock()
	defer mu.Unlock()
	name := c.Info().Name
	if _, exists := byName[name]; exists {
		panic("codec: duplicate registration for " + name)
	}
	byName[name] = c
}

// Get returns a codec by identifier.
func Get(name string) (registry.Codec, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := byName[name]
	return c, ok
}

// All returns registered codecs sorted by name.
func All() []registry.Codec {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]registry.Codec, 0, len(byName))
	for _, c := range byName {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}

// Names returns registered codec identifiers sorted by name.
func Names() []string {
	all := All()
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = c.Info().Name
	}
	return out
}

// FixedWidth returns the element width of a sequence codec whose input must be
// a multiple of a fixed number of bytes. Single-value and text codecs do not
// report a width.
func FixedWidth(name string) (int, bool) {
	c, ok := Get(name)
	if !ok {
		return 0, false
	}
	provider, ok := c.(interface{ Width() int })
	if !ok {
		return 0, false
	}
	width := provider.Width()
	if width < 1 {
		return 0, false
	}
	return width, true
}

// ExactWidth returns the required input width of a single-value codec. Such a
// codec accepts exactly this many bytes and cannot represent multiples of it.
func ExactWidth(name string) (int, bool) {
	c, ok := Get(name)
	if !ok {
		return 0, false
	}
	provider, ok := c.(interface{ ExactWidth() int })
	if !ok {
		return 0, false
	}
	width := provider.ExactWidth()
	if width < 1 {
		return 0, false
	}
	return width, true
}

// ListCodec returns the sequence codec corresponding to a single-value
// fixed-width codec, or an empty string when there is none.
func ListCodec(name string) string { return listCodecFor(name) }
