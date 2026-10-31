// Package cryptography implements ByteForge's cipher registry.
//
// All cryptographic primitives come from maintained implementations:
// crypto/aes, crypto/cipher, golang.org/x/crypto/chacha20poly1305, and
// crypto/rc4. ByteForge does not implement ciphers from scratch.
//
// Container cipher IDs are stable identifiers written to encrypted files. Do
// not renumber them: the IDs are part of the on-disk format.
package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sort"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/registry"
)

// Stable container identifiers. Never renumber.
const (
	IDAES256GCM    byte = 1
	IDAES128GCM    byte = 2
	IDChaCha20Poly byte = 3
	IDAES256CBC    byte = 4
	IDAES256CTR    byte = 5
	IDRC4          byte = 6
)

var (
	mu     sync.RWMutex
	byName = map[string]registry.Cipher{}
	byID   = map[byte]registry.Cipher{}
)

// Register adds a cipher with its stable container ID.
func Register(c registry.Cipher, id byte) {
	mu.Lock()
	defer mu.Unlock()
	name := c.Info().Name
	if _, exists := byName[name]; exists {
		panic("cryptography: duplicate cipher name " + name)
	}
	if _, exists := byID[id]; exists {
		panic(fmt.Sprintf("cryptography: duplicate cipher id %d", id))
	}
	byName[name] = c
	byID[id] = c
}

// Get returns a cipher by identifier.
func Get(name string) (registry.Cipher, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := byName[name]
	return c, ok
}

// ByID returns a cipher by its container identifier.
func ByID(id byte) (registry.Cipher, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := byID[id]
	return c, ok
}

// ID returns the container identifier for a cipher name.
func ID(name string) (byte, bool) {
	mu.RLock()
	defer mu.RUnlock()
	for id, c := range byID {
		if c.Info().Name == name {
			return id, true
		}
	}
	return 0, false
}

// All returns registered ciphers sorted by name.
func All() []registry.Cipher {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]registry.Cipher, 0, len(byName))
	for _, c := range byName {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Info().Name < out[j].Info().Name })
	return out
}

// Names returns cipher identifiers sorted by name.
func Names() []string {
	all := All()
	out := make([]string, len(all))
	for i, c := range all {
		out[i] = c.Info().Name
	}
	return out
}

// RandomBytes returns n bytes from the operating system CSPRNG.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, bferrors.New(bferrors.Processing, "invalid random byte count %d", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "secure random generation failed")
	}
	return b, nil
}

// ---------------------------------------------------------------- AEAD

type aeadCipher struct {
	name     string
	desc     string
	security string
	keySize  int
	newAEAD  func(key []byte) (cipher.AEAD, error)
}

func (c *aeadCipher) Info() registry.Info {
	return registry.Info{
		Name:        c.name,
		Description: c.desc,
		Security:    c.security,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "authenticated ciphertext",
		Parameters: []string{
			fmt.Sprintf("key: %d bytes", c.keySize),
			fmt.Sprintf("nonce: %d bytes (never reuse with the same key)", c.NonceSize()),
			fmt.Sprintf("tag: %d bytes", c.TagSize()),
		},
	}
}

func (c *aeadCipher) KeySize() int   { return c.keySize }
func (c *aeadCipher) NonceSize() int { return 12 }
func (c *aeadCipher) TagSize() int   { return 16 }

func (c *aeadCipher) CiphertextLen(plaintextLen int) int { return plaintextLen }

func (c *aeadCipher) validate(key, nonce []byte) error {
	if len(key) != c.KeySize() {
		return bferrors.New(bferrors.Usage, "%s requires a %d-byte key, got %d", c.name, c.KeySize(), len(key))
	}
	if len(nonce) != c.NonceSize() {
		return bferrors.New(bferrors.Usage, "%s requires a %d-byte nonce, got %d", c.name, c.NonceSize(), len(nonce))
	}
	return nil
}

func (c *aeadCipher) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	if err := c.validate(key, nonce); err != nil {
		return nil, nil, err
	}
	aead, err := c.newAEAD(key)
	if err != nil {
		return nil, nil, bferrors.Wrap(bferrors.Processing, err, "initializing %s", c.name)
	}
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	tagSize := aead.Overhead()
	ctLen := len(sealed) - tagSize
	ct := make([]byte, ctLen)
	copy(ct, sealed[:ctLen])
	tag := make([]byte, tagSize)
	copy(tag, sealed[ctLen:])
	return ct, tag, nil
}

func (c *aeadCipher) Decrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if err := c.validate(key, nonce); err != nil {
		return nil, err
	}
	if len(tag) != c.TagSize() {
		return nil, bferrors.New(bferrors.Verification, "%s: invalid tag length %d", c.name, len(tag))
	}
	aead, err := c.newAEAD(key)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "initializing %s", c.name)
	}
	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	pt, err := aead.Open(nil, nonce, combined, aad)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Verification, err, "%s authentication failed (wrong key or corrupted data)", c.name)
	}
	return pt, nil
}

func init() {
	Register(&aeadCipher{
		name:     "aes-256-gcm",
		desc:     "AES-256-GCM authenticated encryption (preferred default)",
		security: registry.SecurityAuthenticated,
		keySize:  32,
		newAEAD: func(k []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		},
	}, IDAES256GCM)

	Register(&aeadCipher{
		name:     "aes-128-gcm",
		desc:     "AES-128-GCM authenticated encryption",
		security: registry.SecurityAuthenticated,
		keySize:  16,
		newAEAD: func(k []byte) (cipher.AEAD, error) {
			b, err := aes.NewCipher(k)
			if err != nil {
				return nil, err
			}
			return cipher.NewGCM(b)
		},
	}, IDAES128GCM)

	Register(&aeadCipher{
		name:     "chacha20-poly1305",
		desc:     "ChaCha20-Poly1305 AEAD (RFC 8439)",
		security: registry.SecurityAuthenticated,
		keySize:  32,
		newAEAD:  chacha20poly1305.New,
	}, IDChaCha20Poly)

	registerCompatibility()
}
