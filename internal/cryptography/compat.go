package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha256"
	"fmt"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/registry"
)

// Compatibility and legacy ciphers.
//
// aes-256-cbc, aes-256-ctr, and rc4 are not authenticated by themselves. This
// adapter adds encrypt-then-MAC authentication with HMAC-SHA256 over the
// container AAD and ciphertext, using a separate key derived with HKDF-SHA256.
// Authentication is always verified before decryption.

const compatTagSize = 32

func registerCompatibility() {
	Register(&cbcCipher{}, IDAES256CBC)
	Register(&ctrCipher{}, IDAES256CTR)
	Register(&rc4Cipher{}, IDRC4)
}

// deriveKeys expands key material into independent encryption and MAC keys.
func deriveKeys(key []byte, label string) (encKey, macKey []byte, err error) {
	km, err := hkdf.Key(sha256.New, key, nil, "byteforge/"+label+"/v1", 64)
	if err != nil {
		return nil, nil, bferrors.Wrap(bferrors.Processing, err, "deriving subkeys for %s", label)
	}
	return km[:32], km[32:], nil
}

func computeTag(macKey, nonce, aad, ciphertext []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write(nonce)
	m.Write(aad)
	m.Write(ciphertext)
	return m.Sum(nil)
}

func verifyTag(macKey, nonce, aad, ciphertext, tag []byte) error {
	want := computeTag(macKey, nonce, aad, ciphertext)
	if !hmac.Equal(want, tag) {
		return bferrors.New(bferrors.Verification, "authentication failed (wrong key or corrupted data)")
	}
	return nil
}

func checkKeyNonce(name string, key, nonce []byte, keySize, nonceSize int) error {
	if len(key) != keySize {
		return bferrors.New(bferrors.Usage, "%s requires a %d-byte key, got %d", name, keySize, len(key))
	}
	if len(nonce) != nonceSize {
		return bferrors.New(bferrors.Usage, "%s requires a %d-byte IV/nonce, got %d", name, nonceSize, len(nonce))
	}
	return nil
}

// ---------------------------------------------------------------- AES-256-CBC + HMAC

type cbcCipher struct{}

func (cbcCipher) Info() registry.Info {
	return registry.Info{
		Name:        "aes-256-cbc",
		Description: "AES-256-CBC with PKCS#7 padding and encrypt-then-MAC (compatibility mode)",
		Security:    registry.SecurityCompatibility,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "authenticated ciphertext",
		Parameters: []string{
			"key: 32 bytes",
			"IV: 16 bytes",
			"padding: PKCS#7",
			"authentication: HMAC-SHA256 with HKDF-derived MAC key",
		},
		Warning: "CBC is a compatibility mode; prefer aes-256-gcm for new data.",
	}
}

func (cbcCipher) KeySize() int   { return 32 }
func (cbcCipher) NonceSize() int { return aes.BlockSize }
func (cbcCipher) TagSize() int   { return compatTagSize }

func (cbcCipher) CiphertextLen(plaintextLen int) int {
	return (plaintextLen/aes.BlockSize + 1) * aes.BlockSize
}

func (cbcCipher) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	if err := checkKeyNonce("aes-256-cbc", key, nonce, 32, aes.BlockSize); err != nil {
		return nil, nil, err
	}
	encKey, macKey, err := deriveKeys(key, "aes-256-cbc")
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, bferrors.Wrap(bferrors.Processing, err, "initializing aes-256-cbc")
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, nonce).CryptBlocks(ct, padded)
	return ct, computeTag(macKey, nonce, aad, ct), nil
}

func (cbcCipher) Decrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if err := checkKeyNonce("aes-256-cbc", key, nonce, 32, aes.BlockSize); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, bferrors.New(bferrors.Verification, "aes-256-cbc: ciphertext length is not a multiple of the block size")
	}
	encKey, macKey, err := deriveKeys(key, "aes-256-cbc")
	if err != nil {
		return nil, err
	}
	if err := verifyTag(macKey, nonce, aad, ciphertext, tag); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "initializing aes-256-cbc")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, nonce).CryptBlocks(plain, ciphertext)
	out, err := pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Verification, err, "aes-256-cbc: invalid padding")
	}
	return out, nil
}

// ---------------------------------------------------------------- AES-256-CTR + HMAC

type ctrCipher struct{}

func (ctrCipher) Info() registry.Info {
	return registry.Info{
		Name:        "aes-256-ctr",
		Description: "AES-256-CTR with encrypt-then-MAC (compatibility mode)",
		Security:    registry.SecurityCompatibility,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "authenticated ciphertext",
		Parameters: []string{
			"key: 32 bytes",
			"IV: 16 bytes",
			"padding: none",
			"authentication: HMAC-SHA256 with HKDF-derived MAC key",
		},
		Warning: "CTR is a compatibility mode; prefer aes-256-gcm for new data.",
	}
}

func (ctrCipher) KeySize() int                       { return 32 }
func (ctrCipher) NonceSize() int                     { return aes.BlockSize }
func (ctrCipher) TagSize() int                       { return compatTagSize }
func (ctrCipher) CiphertextLen(plaintextLen int) int { return plaintextLen }

func (ctrCipher) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	if err := checkKeyNonce("aes-256-ctr", key, nonce, 32, aes.BlockSize); err != nil {
		return nil, nil, err
	}
	encKey, macKey, err := deriveKeys(key, "aes-256-ctr")
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, bferrors.Wrap(bferrors.Processing, err, "initializing aes-256-ctr")
	}
	ct := make([]byte, len(plaintext))
	cipher.NewCTR(block, nonce).XORKeyStream(ct, plaintext)
	return ct, computeTag(macKey, nonce, aad, ct), nil
}

func (ctrCipher) Decrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if err := checkKeyNonce("aes-256-ctr", key, nonce, 32, aes.BlockSize); err != nil {
		return nil, err
	}
	encKey, macKey, err := deriveKeys(key, "aes-256-ctr")
	if err != nil {
		return nil, err
	}
	if err := verifyTag(macKey, nonce, aad, ciphertext, tag); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "initializing aes-256-ctr")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCTR(block, nonce).XORKeyStream(plain, ciphertext)
	return plain, nil
}

// ---------------------------------------------------------------- RC4 + HMAC (legacy)

type rc4Cipher struct{}

func (rc4Cipher) Info() registry.Info {
	return registry.Info{
		Name:        "rc4",
		Description: "RC4 stream cipher with encrypt-then-MAC (legacy only, disabled by default)",
		Security:    registry.SecurityLegacy,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "authenticated ciphertext",
		Parameters: []string{
			"key: 32 bytes",
			"IV: 16 bytes",
			"authentication: HMAC-SHA256 with HKDF-derived MAC key",
			"requires --allow-legacy",
		},
		Warning: "RC4 is obsolete and unsuitable for protecting sensitive data. Use only for legacy interoperability or demonstrations.",
	}
}

func (rc4Cipher) KeySize() int                       { return 32 }
func (rc4Cipher) NonceSize() int                     { return aes.BlockSize }
func (rc4Cipher) TagSize() int                       { return compatTagSize }
func (rc4Cipher) CiphertextLen(plaintextLen int) int { return plaintextLen }

func (rc4Cipher) Encrypt(key, nonce, plaintext, aad []byte) ([]byte, []byte, error) {
	if err := checkKeyNonce("rc4", key, nonce, 32, aes.BlockSize); err != nil {
		return nil, nil, err
	}
	encKey, macKey, err := deriveKeys(key, "rc4")
	if err != nil {
		return nil, nil, err
	}
	stream, err := rc4.NewCipher(encKey)
	if err != nil {
		return nil, nil, bferrors.Wrap(bferrors.Processing, err, "initializing rc4")
	}
	ct := make([]byte, len(plaintext))
	stream.XORKeyStream(ct, plaintext)
	return ct, computeTag(macKey, nonce, aad, ct), nil
}

func (rc4Cipher) Decrypt(key, nonce, ciphertext, tag, aad []byte) ([]byte, error) {
	if err := checkKeyNonce("rc4", key, nonce, 32, aes.BlockSize); err != nil {
		return nil, err
	}
	encKey, macKey, err := deriveKeys(key, "rc4")
	if err != nil {
		return nil, err
	}
	if err := verifyTag(macKey, nonce, aad, ciphertext, tag); err != nil {
		return nil, err
	}
	stream, err := rc4.NewCipher(encKey)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "initializing rc4")
	}
	plain := make([]byte, len(ciphertext))
	stream.XORKeyStream(plain, ciphertext)
	return plain, nil
}

// ---------------------------------------------------------------- padding

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length %d", len(data))
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("invalid padding length %d", pad)
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, fmt.Errorf("inconsistent padding bytes")
		}
	}
	return data[:len(data)-pad], nil
}
