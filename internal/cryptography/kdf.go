package cryptography

import (
	"golang.org/x/crypto/scrypt"

	"github.com/zoro/byteforge/internal/bferrors"
)

// KDF identifiers stored in the container.
const (
	KDFNone         byte = 0
	KDFScryptSHA256 byte = 1
)

// scrypt parameters for container version 1. These are fixed for the version
// and documented in docs/FORMATS.md; they are not attacker-controlled.
const (
	ScryptN       = 1 << 15
	ScryptR       = 8
	ScryptP       = 1
	ScryptKeyLen  = 32
	ScryptSaltLen = 16
)

// KDFName returns a human-readable name for a container KDF identifier.
func KDFName(id byte) string {
	switch id {
	case KDFNone:
		return "none"
	case KDFScryptSHA256:
		return "scrypt-sha256"
	default:
		return "unknown"
	}
}

// NewSalt returns a fresh random KDF salt.
func NewSalt() ([]byte, error) {
	salt, err := RandomBytes(ScryptSaltLen)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "generating KDF salt")
	}
	return salt, nil
}

// DeriveKey derives a 32-byte key from a password using scrypt.
func DeriveKey(password, salt []byte) ([]byte, error) {
	return DeriveKeySize(password, salt, ScryptKeyLen)
}

// DeriveKeySize derives keyLen bytes from a password using scrypt.
//
// Container version 1 uses the selected cipher's key size: 32 bytes for
// AES-256 and ChaCha20-Poly1305, and 16 bytes for AES-128-GCM. The parameters
// other than keyLen are fixed and are not read from the container.
func DeriveKeySize(password, salt []byte, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, bferrors.New(bferrors.Usage, "password must not be empty")
	}
	if len(salt) != ScryptSaltLen {
		return nil, bferrors.New(bferrors.Usage, "scrypt salt must be %d bytes, got %d", ScryptSaltLen, len(salt))
	}
	if keyLen != 16 && keyLen != 32 {
		return nil, bferrors.New(bferrors.Usage, "scrypt key length must be 16 or 32 bytes, got %d", keyLen)
	}
	key, err := scrypt.Key(password, salt, ScryptN, ScryptR, ScryptP, keyLen)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "scrypt key derivation failed")
	}
	return key, nil
}
