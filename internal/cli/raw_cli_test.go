package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixedKeyHex() string { return strings.Repeat("11", 32) }

func fixedKeyBytes(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString(fixedKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pkcs7PadTest(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(append([]byte{}, data...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func TestRawCBCZeroIVMatchesStandardAES(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("raw cbc interoperability")
	in := writeFile(t, dir, "in.bin", plaintext)
	raw := filepath.Join(dir, "raw.bin")

	r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--zero-iv", "--allow-legacy",
		"--output", raw, "--no-banner")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "Verification") || !strings.Contains(r.stderr, "PASSED") {
		t.Fatalf("missing verification report: %s", r.stderr)
	}
	if !strings.Contains(r.stderr, "none (raw)") {
		t.Fatalf("report does not identify raw output: %s", r.stderr)
	}

	blob, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(blob, []byte("BFRG")) {
		t.Fatal("raw output still starts with the BFRG magic")
	}
	if len(blob) != aes.BlockSize+32 {
		t.Fatalf("raw output length = %d, want %d", len(blob), aes.BlockSize+32)
	}
	if !bytes.Equal(blob[:aes.BlockSize], make([]byte, aes.BlockSize)) {
		t.Fatalf("IV = %x, want all-zero", blob[:aes.BlockSize])
	}

	block, err := aes.NewCipher(fixedKeyBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7PadTest(plaintext, aes.BlockSize)
	want := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(want, padded)
	if !bytes.Equal(blob[aes.BlockSize:], want) {
		t.Fatalf("raw ciphertext = %x, want standard AES-CBC %x", blob[aes.BlockSize:], want)
	}

	recovered := filepath.Join(dir, "recovered.bin")
	r = run(t, "", "decrypt", "--file", raw, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--allow-legacy",
		"--output", recovered, "--no-banner")
	if r.code != 0 {
		t.Fatalf("decrypt exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered = %q, want %q", got, plaintext)
	}
}

func TestRawCBCRequiresNoContainer(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))

	r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--allow-legacy", "--no-banner")
	if r.code != 2 {
		t.Fatalf("raw cipher in container mode exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "raw-only") || !strings.Contains(r.stderr, "--no-container") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}
}

func TestRawCBCRequiresAllowLegacy(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))

	r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}

	r = run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--allow-legacy", "--output", filepath.Join(dir, "raw.bin"), "--no-banner")
	if r.code != 0 {
		t.Fatalf("with --allow-legacy exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "unauthenticated") {
		t.Fatalf("missing legacy warning: %s", r.stderr)
	}
}

func TestRawCBCRejectsAADAndNonceConflicts(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))

	r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--allow-legacy", "--aad", "context", "--no-banner")
	if r.code != 2 {
		t.Fatalf("--aad exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "--aad is not available with --no-container") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}

	nonce := strings.Repeat("22", aes.BlockSize)
	r = run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--allow-legacy",
		"--zero-iv", "--nonce", nonce, "--no-banner")
	if r.code != 2 {
		t.Fatalf("--zero-iv with --nonce exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
}

func TestRawDecryptRequiresExplicitKeyAndCipher(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	raw := filepath.Join(dir, "raw.bin")
	if r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--allow-legacy",
		"--output", raw, "--no-banner"); r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}

	r := run(t, "", "decrypt", "--file", raw, "--cipher", "aes-256-cbc-raw",
		"--password", "pw", "--no-container", "--allow-legacy", "--no-banner")
	if r.code != 2 {
		t.Fatalf("password raw decrypt exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "no KDF salt") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}

	r = run(t, "", "decrypt", "--file", raw, "--no-container",
		"--key", fixedKeyHex(), "--allow-legacy", "--no-banner")
	if r.code != 2 {
		t.Fatalf("missing --cipher exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "--cipher is required") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}
}

func TestRawPasswordNeedsKeyCarrier(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))

	r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--password", "pw", "--no-container", "--allow-legacy", "--no-banner")
	if r.code != 2 {
		t.Fatalf("password raw with raw renderer exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "does not store the KDF salt") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}

	// A key-capable renderer carries the derived key, so the salt is not needed.
	r = run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--password", "pw", "--no-container", "--allow-legacy",
		"--renderer", "c-array", "--no-banner")
	if r.code != 0 {
		t.Fatalf("password raw with c-array exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(string(r.stdout), "unsigned char key[]") {
		t.Fatal("key-capable raw output did not include the derived key")
	}

	// --export-key is also a valid carrier for password-based raw output.
	keyFile := filepath.Join(dir, "key.txt")
	r = run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--password", "pw", "--no-container", "--allow-legacy",
		"--export-key", keyFile, "--output", filepath.Join(dir, "raw.bin"), "--no-banner")
	if r.code != 0 {
		t.Fatalf("password raw with --export-key exit %d: %s", r.code, r.stderr)
	}
	exported, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(exported))) != 64 {
		t.Fatalf("exported key is not 32 bytes of hex: %q", exported)
	}
}

func TestRawGCMRoundTrip(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("raw authenticated payload")
	in := writeFile(t, dir, "in.bin", plaintext)
	raw := filepath.Join(dir, "raw.bin")
	recovered := filepath.Join(dir, "recovered.bin")

	if r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-gcm",
		"--key", fixedKeyHex(), "--no-container", "--output", raw, "--no-banner"); r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	blob, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 12+len(plaintext)+16 {
		t.Fatalf("raw GCM length = %d, want %d", len(blob), 12+len(plaintext)+16)
	}
	if bytes.HasPrefix(blob, []byte("BFRG")) {
		t.Fatal("raw GCM output still starts with the BFRG magic")
	}

	if r := run(t, "", "decrypt", "--file", raw, "--cipher", "aes-256-gcm",
		"--key", fixedKeyHex(), "--no-container", "--output", recovered, "--no-banner"); r.code != 0 {
		t.Fatalf("decrypt exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("recovered = %q, want %q", got, plaintext)
	}

	// Any single-bit change must fail authentication before plaintext is written.
	blob[len(blob)-1] ^= 0x01
	tampered := filepath.Join(dir, "tampered.bin")
	if err := os.WriteFile(tampered, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "must-not-exist.bin")
	r := run(t, "", "decrypt", "--file", tampered, "--cipher", "aes-256-gcm",
		"--key", fixedKeyHex(), "--no-container", "--output", out, "--no-banner")
	if r.code != 4 {
		t.Fatalf("tampered raw GCM exit = %d, want 4; stderr: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("plaintext was written on authentication failure")
	}
}

func TestRawModeWarnsForHKDFCiphers(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	out := filepath.Join(dir, "raw.bin")

	r := run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc",
		"--key", fixedKeyHex(), "--no-container", "--output", out, "--no-banner")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "only removes BFRG framing") ||
		!strings.Contains(r.stderr, "base key, not the AES key") ||
		!strings.Contains(r.stderr, "aes-256-cbc-raw") {
		t.Fatalf("missing HKDF raw-mode warning: %s", r.stderr)
	}

	// The warning must not fire for the direct-key cipher.
	r = run(t, "", "encrypt", "--file", in, "--cipher", "aes-256-cbc-raw",
		"--key", fixedKeyHex(), "--no-container", "--allow-legacy",
		"--output", filepath.Join(dir, "raw-raw.bin"), "--no-banner")
	if r.code != 0 {
		t.Fatalf("raw CBC exit %d: %s", r.code, r.stderr)
	}
	if strings.Contains(r.stderr, "base key, not the AES key") {
		t.Fatalf("direct-key cipher received the HKDF warning: %s", r.stderr)
	}
}

func TestContainerDecryptRejectsCipherFlag(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	ct := filepath.Join(dir, "sample.bf")
	if r := run(t, "pw\n", "encrypt", "--file", in, "--password-stdin", "--output", ct, "--no-banner"); r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}

	r := run(t, "", "decrypt", "--file", ct, "--cipher", "aes-256-gcm",
		"--password", "pw", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "only used with --no-container") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}
}
