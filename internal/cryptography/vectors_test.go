package cryptography

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoro/byteforge/internal/container"
)

// TestContainerVectors checks the published golden containers in testdata/.
// If a vector changes, docs/FORMATS.md and the testdata README must change too.
func TestContainerVectors(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	plaintext, err := os.ReadFile(filepath.Join(root, "plaintext", "ByteForge.bin"))
	if err != nil {
		t.Fatal(err)
	}

	key256, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	key128, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		file     string
		cipher   string
		key      []byte
		password []byte
		aad      []byte
		sha256   string
	}{
		{
			file:   "gcm-key.bf",
			cipher: "aes-256-gcm",
			key:    key256,
			sha256: "ae44837b860d22d241f57410e31749bcc9bad6a407bfd5f29a12f1d1872fe8c9",
		},
		{
			file:   "gcm128-key.bf",
			cipher: "aes-128-gcm",
			key:    key128,
			sha256: "7e47e826a9293f7aa5bd1db658f0ea2410233fb45f66426555055bb193cb571e",
		},
		{
			file:   "chacha-key.bf",
			cipher: "chacha20-poly1305",
			key:    key256,
			sha256: "1fee755f977abde6baf5a0a4f7ddd2ead113ba5f727742e967611d0742898535",
		},
		{
			file:   "cbc-key.bf",
			cipher: "aes-256-cbc",
			key:    key256,
			sha256: "52b28e53244e1501250f51021b58a0203754dfe482b38c05e4c9b45622e21ba9",
		},
		{
			file:     "gcm-password.bf",
			cipher:   "aes-256-gcm",
			password: []byte("correct horse battery staple"),
			sha256:   "a2e0553480bb2105b18d337397b7cd800b912ad79c20100f4b05367df4b533cc",
		},
		{
			file:   "gcm-key-aad.bf",
			cipher: "aes-256-gcm",
			key:    key256,
			aad:    []byte("context=v1"),
			sha256: "b6f008f95e6e43601fc318bb5c769e6e6e9efc1d2f1bbb07aafc7b496065f2f9",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			blob, err := os.ReadFile(filepath.Join(root, "containers", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			hexFile, err := os.ReadFile(filepath.Join(root, "containers", strings.TrimSuffix(tc.file, ".bf")+".hex"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(hexFile)) != hex.EncodeToString(blob) {
				t.Fatal("hex vector does not match binary vector")
			}
			if got := sha256HexForTest(blob); got != tc.sha256 {
				t.Fatalf("vector SHA-256 = %s, want %s", got, tc.sha256)
			}

			parsed, err := container.Parse(blob, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			c, ok := ByID(parsed.Header.CipherID)
			if !ok || c.Info().Name != tc.cipher {
				t.Fatalf("cipher id %d = %v, want %s", parsed.Header.CipherID, ok, tc.cipher)
			}

			key := tc.key
			if tc.password != nil {
				if parsed.Header.KDFID != KDFScryptSHA256 {
					t.Fatalf("password vector KDF id = %d", parsed.Header.KDFID)
				}
				key, err = DeriveKey(tc.password, parsed.Header.Salt)
				if err != nil {
					t.Fatal(err)
				}
			} else if parsed.Header.KDFID != KDFNone {
				t.Fatalf("key vector KDF id = %d", parsed.Header.KDFID)
			}

			got, err := c.Decrypt(key, parsed.Header.Nonce, parsed.Ciphertext, parsed.Tag, parsed.AAD(tc.aad))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext = %q, want %q", got, plaintext)
			}

			tampered := append([]byte(nil), blob...)
			tampered[len(tampered)-1] ^= 1
			p, err := container.Parse(tampered, 1<<20)
			if err != nil {
				t.Fatalf("tampered vector is structurally invalid: %v", err)
			}
			if _, err := c.Decrypt(key, p.Header.Nonce, p.Ciphertext, p.Tag, p.AAD(tc.aad)); err == nil {
				t.Fatal("tampered vector decrypted successfully")
			}
		})
	}
}

func TestPasswordVectorDerivedKey(t *testing.T) {
	salt, err := hex.DecodeString("101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveKey([]byte("correct horse battery staple"), salt)
	if err != nil {
		t.Fatal(err)
	}
	const want = "4422cc8b14ecaf05e5b234429eac95c3594a6f75c9bdd032fedf5416db8dae48"
	if hex.EncodeToString(key) != want {
		t.Fatalf("derived key = %x, want %s", key, want)
	}
}

func sha256HexForTest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
