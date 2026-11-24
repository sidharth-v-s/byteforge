package cryptography

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/registry"
)

func rawCBCCipherForTest(t *testing.T) registry.Cipher {
	t.Helper()
	c, ok := Get("aes-256-cbc-raw")
	if !ok {
		t.Fatal("aes-256-cbc-raw is not registered")
	}
	return c
}

func TestRawCBCMatchesStandardAES(t *testing.T) {
	c := rawCBCCipherForTest(t)
	key := keyFor(c)
	nonce := nonceFor(c)

	for _, pt := range [][]byte{
		{},
		{0x00},
		[]byte("hello"),
		bytes.Repeat([]byte{0x5a}, 15),
		bytes.Repeat([]byte{0x5a}, 16),
		bytes.Repeat([]byte{0x5a}, 17),
		bytes.Repeat([]byte{0x5a}, 1024),
	} {
		ct, tag, err := c.Encrypt(key, nonce, pt, nil)
		if err != nil {
			t.Fatalf("encrypt %d bytes: %v", len(pt), err)
		}
		if len(tag) != 0 {
			t.Fatalf("tag size = %d, want 0 for raw CBC", len(tag))
		}
		if len(ct)%aes.BlockSize != 0 {
			t.Fatalf("ciphertext length %d is not block aligned", len(ct))
		}
		if len(ct) != c.CiphertextLen(len(pt)) {
			t.Fatalf("CiphertextLen(%d) = %d, actual %d", len(pt), c.CiphertextLen(len(pt)), len(ct))
		}

		// Independently construct standard AES-256-CBC with PKCS#7 padding.
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, len(pkcs7Pad(pt, aes.BlockSize)))
		cipher.NewCBCEncrypter(block, nonce).CryptBlocks(want, pkcs7Pad(pt, aes.BlockSize))
		if !bytes.Equal(ct, want) {
			t.Fatalf("raw CBC ciphertext differs from standard AES-CBC for %d-byte plaintext", len(pt))
		}

		got, err := c.Decrypt(key, nonce, ct, nil, nil)
		if err != nil {
			t.Fatalf("decrypt %d bytes: %v", len(pt), err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip mismatch for %d bytes", len(pt))
		}
	}
}

func TestRawCBCRejectsAADAndTags(t *testing.T) {
	c := rawCBCCipherForTest(t)
	key := keyFor(c)
	nonce := nonceFor(c)

	if _, _, err := c.Encrypt(key, nonce, []byte("x"), []byte("aad")); err == nil {
		t.Fatal("raw CBC accepted AAD")
	} else if bferrors.KindOf(err) != bferrors.Usage {
		t.Fatalf("AAD error kind = %v, want Usage", bferrors.KindOf(err))
	}

	ct, _, err := c.Encrypt(key, nonce, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decrypt(key, nonce, ct, []byte{0x01}, nil); err == nil {
		t.Fatal("raw CBC accepted a non-empty tag")
	}
	if _, err := c.Decrypt(key, nonce, ct[:len(ct)-1], nil, nil); err == nil {
		t.Fatal("raw CBC accepted a truncated ciphertext block")
	}
}

func TestRawCBCClassifiedLegacy(t *testing.T) {
	c := rawCBCCipherForTest(t)
	info := c.Info()
	if info.Name != "aes-256-cbc-raw" {
		t.Fatalf("name = %q", info.Name)
	}
	if info.Security != registry.SecurityLegacy {
		t.Fatalf("security = %v, want legacy", info.Security)
	}
	if c.KeySize() != 32 || c.NonceSize() != aes.BlockSize || c.TagSize() != 0 {
		t.Fatalf("unexpected sizes: key=%d nonce=%d tag=%d", c.KeySize(), c.NonceSize(), c.TagSize())
	}
}
