// Package transform implements reversible, non-cryptographic byte
// transformations.
//
// XOR is an obfuscation transform, not encryption. It is grouped separately
// from cryptographic algorithms in `byteforge formats` and must never be
// presented as secure protection.
package transform

import (
	"fmt"
	"sort"
	"sync"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/registry"
)

var (
	mu     sync.RWMutex
	byName = map[string]registry.Transform{}
)

// Register adds a transform. Duplicate names are a programming error.
func Register(t registry.Transform) {
	mu.Lock()
	defer mu.Unlock()
	name := t.Info().Name
	if _, exists := byName[name]; exists {
		panic("transform: duplicate registration for " + name)
	}
	byName[name] = t
}

// Get returns a transform by identifier.
func Get(name string) (registry.Transform, bool) {
	mu.RLock()
	defer mu.RUnlock()
	t, ok := byName[name]
	return t, ok
}

// All returns registered transforms sorted by name.
func All() []registry.Transform {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]registry.Transform, 0, len(byName))
	for _, t := range byName {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}

// Names returns transform identifiers sorted by name.
func Names() []string {
	all := All()
	out := make([]string, len(all))
	for i, t := range all {
		out[i] = t.Info().Name
	}
	return out
}

func init() {
	Register(xorSingleByte{})
	Register(xorRepeatingKey{})
}

// ---------------------------------------------------------------- xor-single-byte

type xorSingleByte struct{}

func (xorSingleByte) Info() registry.Info {
	return registry.Info{
		Name:        "xor-single-byte",
		Description: "XOR every byte with one key byte (educational obfuscation)",
		Security:    registry.SecurityTransform,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "transformed bytes",
		Parameters:  []string{"key: exactly 1 byte, hex"},
		Warning:     "Not encryption. XOR provides no meaningful confidentiality.",
	}
}

func (xorSingleByte) ValidateKey(key []byte) error {
	if len(key) != 1 {
		return bferrors.New(bferrors.Usage, "xor-single-byte requires a 1-byte key, got %d bytes", len(key))
	}
	return nil
}

func (xorSingleByte) Apply(data, key []byte) ([]byte, error) {
	if err := (xorSingleByte{}).ValidateKey(key); err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[0]
	}
	return out, nil
}

// ---------------------------------------------------------------- xor-repeating-key

type xorRepeatingKey struct{}

func (xorRepeatingKey) Info() registry.Info {
	return registry.Info{
		Name:        "xor-repeating-key",
		Description: "XOR with a repeating key (educational obfuscation)",
		Security:    registry.SecurityTransform,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "transformed bytes",
		Parameters:  []string{"key: 1-256 bytes, hex"},
		Warning:     "Not encryption. Repeating-key XOR is trivially breakable.",
	}
}

func (xorRepeatingKey) ValidateKey(key []byte) error {
	if len(key) < 1 || len(key) > 256 {
		return bferrors.New(bferrors.Usage, "xor-repeating-key requires a key of 1-256 bytes, got %d", len(key))
	}
	return nil
}

func (xorRepeatingKey) Apply(data, key []byte) ([]byte, error) {
	if err := (xorRepeatingKey{}).ValidateKey(key); err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out, nil
}

// KeyDescription is used in error messages for key flags.
func KeyDescription(t registry.Transform) string {
	switch t.Info().Name {
	case "xor-single-byte":
		return "a 1-byte hex key (e.g. --key 5a)"
	case "xor-repeating-key":
		return "a 1-256 byte hex key (e.g. --key 5a17c3)"
	default:
		return fmt.Sprintf("a valid key for %s", t.Info().Name)
	}
}
