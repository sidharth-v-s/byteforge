package cryptography

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/zoro/byteforge/internal/bferrors"
)

func keyFor(c interface{ KeySize() int }) []byte {
	k := make([]byte, c.KeySize())
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func nonceFor(c interface{ NonceSize() int }) []byte {
	n := make([]byte, c.NonceSize())
	for i := range n {
		n[i] = byte(0x80 + i)
	}
	return n
}

func TestRoundTripAllCiphers(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x00},
		[]byte("hello"),
		bytes.Repeat([]byte{0x5a}, 15),
		bytes.Repeat([]byte{0x5a}, 16),
		bytes.Repeat([]byte{0x5a}, 17),
		bytes.Repeat([]byte{0x5a}, 1024),
	}
	aad := []byte("container header context")
	for _, c := range All() {
		c := c
		t.Run(c.Info().Name, func(t *testing.T) {
			key := keyFor(c)
			nonce := nonceFor(c)
			for _, pt := range payloads {
				ct, tag, err := c.Encrypt(key, nonce, pt, aad)
				if err != nil {
					t.Fatalf("encrypt %d bytes: %v", len(pt), err)
				}
				if len(ct) != c.CiphertextLen(len(pt)) {
					t.Fatalf("CiphertextLen(%d) = %d, actual %d", len(pt), c.CiphertextLen(len(pt)), len(ct))
				}
				if len(tag) != c.TagSize() {
					t.Fatalf("tag size %d, want %d", len(tag), c.TagSize())
				}
				got, err := c.Decrypt(key, nonce, ct, tag, aad)
				if err != nil {
					t.Fatalf("decrypt %d bytes: %v", len(pt), err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatalf("round trip mismatch for %d bytes", len(pt))
				}
			}
		})
	}
}

func TestAuthenticationFailures(t *testing.T) {
	pt := []byte("authenticate me, please")
	aad := []byte("aad")
	for _, c := range All() {
		c := c
		t.Run(c.Info().Name, func(t *testing.T) {
			key := keyFor(c)
			nonce := nonceFor(c)
			ct, tag, err := c.Encrypt(key, nonce, pt, aad)
			if err != nil {
				t.Fatal(err)
			}

			assertVerificationFailure := func(label string, got []byte, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s: decryption unexpectedly succeeded", label)
				}
				if got != nil {
					t.Fatalf("%s: plaintext was returned on failure", label)
				}
				if bferrors.KindOf(err) != bferrors.Verification {
					t.Fatalf("%s: error kind = %v, want Verification", label, bferrors.KindOf(err))
				}
			}

			badCT := append([]byte(nil), ct...)
			badCT[0] ^= 1
			got, err := c.Decrypt(key, nonce, badCT, tag, aad)
			assertVerificationFailure("modified ciphertext", got, err)

			badTag := append([]byte(nil), tag...)
			badTag[0] ^= 1
			got, err = c.Decrypt(key, nonce, ct, badTag, aad)
			assertVerificationFailure("modified tag", got, err)

			badNonce := append([]byte(nil), nonce...)
			badNonce[0] ^= 1
			got, err = c.Decrypt(key, badNonce, ct, tag, aad)
			assertVerificationFailure("modified nonce", got, err)

			got, err = c.Decrypt(key, nonce, ct, tag, []byte("different aad"))
			assertVerificationFailure("modified aad", got, err)

			wrongKey := append([]byte(nil), key...)
			wrongKey[0] ^= 1
			got, err = c.Decrypt(wrongKey, nonce, ct, tag, aad)
			assertVerificationFailure("wrong key", got, err)
		})
	}
}

func TestParameterValidation(t *testing.T) {
	for _, c := range All() {
		key := keyFor(c)
		nonce := nonceFor(c)
		if _, _, err := c.Encrypt(key[:len(key)-1], nonce, nil, nil); err == nil {
			t.Fatalf("%s accepted a short key", c.Info().Name)
		}
		if _, _, err := c.Encrypt(key, nonce[:len(nonce)-1], nil, nil); err == nil {
			t.Fatalf("%s accepted a short nonce", c.Info().Name)
		}
		ct, tag, err := c.Encrypt(key, nonce, []byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Decrypt(key, nonce, ct, tag[:len(tag)-1], nil); err == nil {
			t.Fatalf("%s accepted a short tag", c.Info().Name)
		}
	}
}

func TestAESGCMKnownAnswerVectors(t *testing.T) {
	// NIST SP 800-38D, zero key / zero IV / empty plaintext examples.
	c256, _ := Get("aes-256-gcm")
	_, tag256, err := c256.Encrypt(make([]byte, 32), make([]byte, 12), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tag256); got != "530f8afbc74536b9a963b4f1c4cb738b" {
		t.Fatalf("AES-256-GCM tag = %s", got)
	}

	c128, _ := Get("aes-128-gcm")
	_, tag128, err := c128.Encrypt(make([]byte, 16), make([]byte, 12), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tag128); got != "58e2fccefa7e3061367f1d57a4e7455a" {
		t.Fatalf("AES-128-GCM tag = %s", got)
	}
}

func TestCBCPaddingOracleSafety(t *testing.T) {
	// CBC must verify authentication before decrypting; a modified ciphertext
	// is rejected even if it would produce valid PKCS#7 padding.
	c, _ := Get("aes-256-cbc")
	key := keyFor(c)
	nonce := nonceFor(c)
	pt := bytes.Repeat([]byte{0x41}, 32)
	ct, tag, err := c.Encrypt(key, nonce, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 0x01
	if _, err := c.Decrypt(key, nonce, bad, tag, nil); err == nil {
		t.Fatal("modified CBC ciphertext was accepted")
	}
}

func TestRegistryIDsStable(t *testing.T) {
	want := map[string]byte{
		"aes-256-gcm":       IDAES256GCM,
		"aes-128-gcm":       IDAES128GCM,
		"chacha20-poly1305": IDChaCha20Poly,
		"aes-256-cbc":       IDAES256CBC,
		"aes-256-ctr":       IDAES256CTR,
		"rc4":               IDRC4,
	}
	for name, id := range want {
		got, ok := ID(name)
		if !ok || got != id {
			t.Fatalf("ID(%s) = %d, %v; want %d", name, got, ok, id)
		}
		c, ok := ByID(id)
		if !ok || c.Info().Name != name {
			t.Fatalf("ByID(%d) mismatch", id)
		}
	}
}

func TestKDF(t *testing.T) {
	password := []byte("correct horse battery staple")
	salt, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != ScryptSaltLen {
		t.Fatalf("salt length %d", len(salt))
	}
	if allZero(salt) {
		t.Fatal("salt is all zero")
	}

	k1, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("KDF is not deterministic for the same salt")
	}
	otherSalt, _ := NewSalt()
	k3, err := DeriveKey(password, otherSalt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("different salts produced the same key")
	}

	if _, err := DeriveKey(nil, salt); err == nil {
		t.Fatal("accepted empty password")
	}
	if _, err := DeriveKey(password, []byte("short")); err == nil {
		t.Fatal("accepted short salt")
	}

	k16, err := DeriveKeySize(password, salt, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(k16) != 16 {
		t.Fatalf("16-byte derivation returned %d bytes", len(k16))
	}
	if !bytes.Equal(k16, k1[:16]) {
		t.Fatal("16-byte derivation does not match the truncated 32-byte derivation")
	}
	if _, err := DeriveKeySize(password, salt, 20); err == nil {
		t.Fatal("accepted unsupported key length")
	}
}

func TestRandomBytes(t *testing.T) {
	a, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || len(b) != 32 {
		t.Fatal("wrong random length")
	}
	if bytes.Equal(a, b) {
		t.Fatal("two random draws were identical")
	}
	if allZero(a) {
		t.Fatal("random bytes were all zero")
	}
	if _, err := RandomBytes(0); err == nil {
		t.Fatal("accepted zero-length random request")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
