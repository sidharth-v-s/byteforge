package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/zoro/byteforge/internal/container"
	"github.com/zoro/byteforge/internal/cryptography"
)

type result struct {
	code   int
	stdout []byte
	stderr string
}

func run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunWithIO(args, strings.NewReader(stdin), &out, &errb)
	return result{code: code, stdout: out.Bytes(), stderr: errb.String()}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	input := []byte("Hello, ByteForge!\x00\x01\xff")
	in := writeFile(t, dir, "in.bin", input)
	encoded := filepath.Join(dir, "payload.txt")
	recovered := filepath.Join(dir, "out.bin")

	r := run(t, "", "encode", "--file", in, "--encoding", "base64", "--output", encoded, "--no-banner")
	if r.code != 0 {
		t.Fatalf("encode exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "Verification") || !strings.Contains(r.stderr, "PASSED") {
		t.Fatalf("encode report missing verification: %s", r.stderr)
	}

	r = run(t, "", "decode", "--file", encoded, "--encoding", "base64", "--output", recovered, "--no-banner")
	if r.code != 0 {
		t.Fatalf("decode exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("decoded bytes differ from input")
	}
}

func TestNoImplicitInput(t *testing.T) {
	r := run(t, "", "encode", "--encoding", "hex", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, "no input specified") {
		t.Fatalf("unexpected error: %s", r.stderr)
	}
}

func TestNoSilentOverwrite(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{1, 2, 3})
	out := writeFile(t, dir, "out.txt", []byte("existing"))

	r := run(t, "", "encode", "--file", in, "--encoding", "hex", "--output", out, "--no-banner")
	if r.code != 3 {
		t.Fatalf("exit = %d, want 3", r.code)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "existing" {
		t.Fatal("existing output was modified")
	}

	r = run(t, "", "encode", "--file", in, "--encoding", "hex", "--output", out, "--force", "--no-banner")
	if r.code != 0 {
		t.Fatalf("forced encode exit %d: %s", r.code, r.stderr)
	}
	got, _ = os.ReadFile(out)
	if string(got) != "010203" {
		t.Fatalf("forced output = %q", got)
	}
}

func TestExitCodes(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{1, 2, 3})

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"missing file", []string{"encode", "--file", filepath.Join(dir, "nope.bin"), "--encoding", "hex"}, 3},
		{"unknown codec", []string{"encode", "--file", in, "--encoding", "nope"}, 2},
		{"unknown renderer", []string{"encode", "--file", in, "--encoding", "hex", "--renderer", "nope"}, 2},
		{"missing output dir", []string{"encode", "--file", in, "--encoding", "hex", "--output", filepath.Join(dir, "missing", "x.txt")}, 3},
		{"bad hex", []string{"encode", "--hex", "abc", "--encoding", "hex"}, 2},
		{"conflicting input", []string{"encode", "--file", in, "--hex", "00", "--encoding", "hex"}, 2},
		{"unknown cipher", []string{"encrypt", "--file", in, "--cipher", "nope", "--key", strings.Repeat("00", 32)}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, "", append(tc.args, "--no-banner")...)
			if r.code != tc.want {
				t.Fatalf("exit = %d, want %d; stderr: %s", r.code, tc.want, r.stderr)
			}
		})
	}
}

func TestEncryptDecryptPassword(t *testing.T) {
	dir := t.TempDir()
	input := bytes.Repeat([]byte("secret payload;"), 8)
	in := writeFile(t, dir, "in.bin", input)
	ct := filepath.Join(dir, "sample.bf")
	pt := filepath.Join(dir, "recovered.bin")

	r := run(t, "hunter2\n", "encrypt", "--file", in, "--password-stdin", "--output", ct, "--no-banner")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	if strings.Contains(r.stderr, "hunter2") {
		t.Fatal("password leaked into the report")
	}

	r = run(t, "hunter2\n", "decrypt", "--file", ct, "--password-stdin", "--output", pt, "--no-banner")
	if r.code != 0 {
		t.Fatalf("decrypt exit %d: %s", r.code, r.stderr)
	}
	got, _ := os.ReadFile(pt)
	if !bytes.Equal(got, input) {
		t.Fatal("decrypted bytes differ")
	}
}

func TestWrongPasswordAndTamper(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	ct := filepath.Join(dir, "sample.bf")
	if r := run(t, "correct\n", "encrypt", "--file", in, "--password-stdin", "--output", ct, "--no-banner"); r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}

	wrongOut := filepath.Join(dir, "wrong.bin")
	r := run(t, "wrong\n", "decrypt", "--file", ct, "--password-stdin", "--output", wrongOut, "--no-banner")
	if r.code != 4 {
		t.Fatalf("wrong password exit = %d, want 4; stderr: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(wrongOut); !os.IsNotExist(err) {
		t.Fatal("plaintext was written after authentication failure")
	}

	blob, _ := os.ReadFile(ct)
	blob[len(blob)-1] ^= 0x01
	tampered := writeFile(t, dir, "tampered.bf", blob)
	tamperOut := filepath.Join(dir, "tamper.bin")
	r = run(t, "correct\n", "decrypt", "--file", tampered, "--password-stdin", "--output", tamperOut, "--no-banner")
	if r.code != 4 {
		t.Fatalf("tampered container exit = %d, want 4; stderr: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(tamperOut); !os.IsNotExist(err) {
		t.Fatal("plaintext was written for a tampered container")
	}
}

func TestGeneratedKeyExport(t *testing.T) {
	dir := t.TempDir()
	input := []byte("generated key test")
	in := writeFile(t, dir, "in.bin", input)
	ct := filepath.Join(dir, "sample.bf")
	keyFile := filepath.Join(dir, "sample.key")
	pt := filepath.Join(dir, "out.bin")

	r := run(t, "", "encrypt", "--file", in, "--output", ct, "--export-key", keyFile, "--no-banner")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %o, want 600", info.Mode().Perm())
	}

	r = run(t, "", "decrypt", "--file", ct, "--key-file", keyFile, "--output", pt, "--no-banner")
	if r.code != 0 {
		t.Fatalf("decrypt exit %d: %s", r.code, r.stderr)
	}
	got, _ := os.ReadFile(pt)
	if !bytes.Equal(got, input) {
		t.Fatal("generated-key round trip failed")
	}
}

func TestStdoutPurity(t *testing.T) {
	dir := t.TempDir()
	input := []byte{0x00, 0xff, 0x10, 0x41}
	in := writeFile(t, dir, "in.bin", input)

	r := run(t, "", "encode", "--file", in, "--encoding", "raw", "--no-banner")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !bytes.Equal(r.stdout, input) {
		t.Fatalf("stdout = %x, want %x", r.stdout, input)
	}
	if strings.Contains(string(r.stdout), "Operation") {
		t.Fatal("status text leaked into stdout")
	}
	if !strings.Contains(r.stderr, "Operation") {
		t.Fatal("report missing from stderr")
	}

	r = run(t, "", "encode", "--file", in, "--encoding", "base64", "--no-banner")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(r.stdout)))
	if err != nil {
		t.Fatalf("stdout is not clean base64: %v (%q)", err, r.stdout)
	}
	if !bytes.Equal(decoded, input) {
		t.Fatal("stdout payload mismatch")
	}
}

func TestRC4RequiresAllowLegacy(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("legacy"))
	key := strings.Repeat("11", 32)
	ct := filepath.Join(dir, "legacy.bf")

	r := run(t, "", "encrypt", "--file", in, "--cipher", "rc4", "--key", key, "--output", ct, "--no-banner")
	if r.code != 2 {
		t.Fatalf("rc4 without --allow-legacy exit = %d, want 2; stderr: %s", r.code, r.stderr)
	}

	r = run(t, "", "encrypt", "--file", in, "--cipher", "rc4", "--key", key, "--output", ct, "--allow-legacy", "--no-banner")
	if r.code != 0 {
		t.Fatalf("rc4 with --allow-legacy exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "obsolete") {
		t.Fatal("missing legacy warning")
	}

	pt := filepath.Join(dir, "out.bin")
	r = run(t, "", "decrypt", "--file", ct, "--key", key, "--output", pt, "--no-banner")
	if r.code != 2 {
		t.Fatalf("rc4 decrypt without --allow-legacy exit = %d, want 2", r.code)
	}
	r = run(t, "", "decrypt", "--file", ct, "--key", key, "--output", pt, "--allow-legacy", "--no-banner")
	if r.code != 0 {
		t.Fatalf("rc4 decrypt exit %d: %s", r.code, r.stderr)
	}
}

func TestInspectJSON(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("inspect me"))
	ct := filepath.Join(dir, "sample.bf")
	if r := run(t, "pw\n", "encrypt", "--file", in, "--password-stdin", "--output", ct, "--no-banner"); r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}

	r := run(t, "", "inspect", "--file", ct, "--json", "--no-banner")
	if r.code != 0 {
		t.Fatalf("inspect exit %d: %s", r.code, r.stderr)
	}
	var doc struct {
		Size      int64 `json:"size"`
		Container *struct {
			Version byte   `json:"version"`
			Cipher  string `json:"cipher"`
			KDF     string `json:"kdf"`
		} `json:"container"`
	}
	if err := json.Unmarshal(r.stdout, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Container == nil || doc.Container.Version != 1 || doc.Container.Cipher != "aes-256-gcm" || doc.Container.KDF != "scrypt-sha256" {
		t.Fatalf("unexpected container metadata: %+v", doc.Container)
	}
}

func TestVerifyMismatch(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.bin", []byte("one"))
	b := writeFile(t, dir, "b.bin", []byte("two"))

	r := run(t, "", "verify", "--original", a, "--recovered", b, "--no-banner")
	if r.code != 4 {
		t.Fatalf("exit = %d, want 4", r.code)
	}
	if !strings.Contains(string(r.stdout), "FAILED") {
		t.Fatalf("missing FAILED output: %s", r.stdout)
	}

	r = run(t, "", "verify", "--original", a, "--recovered", a, "--no-banner")
	if r.code != 0 {
		t.Fatalf("same-file verify exit = %d", r.code)
	}
}

func TestFormatsGroups(t *testing.T) {
	r := run(t, "", "formats")
	if r.code != 0 {
		t.Fatalf("formats exit %d: %s", r.code, r.stderr)
	}
	out := string(r.stdout)
	for _, want := range []string{
		"Representation codecs",
		"Reversible transforms",
		"Cryptographic algorithms",
		"Compatibility ciphers",
		"Legacy algorithms",
		"Output renderers",
		"aes-256-gcm",
		"xor-single-byte",
		"c-array",
		"csharp-array",
		"rust-array",
		"zig-array",
		"--key-symbol NAME (encrypt; key always included)",
		"Payload padding",
		"--pad MODE",
		"--pad-to N",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("formats output missing %q", want)
		}
	}
}

func TestLanguageRendererCLI(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{0x00, 0x41, 0xff})
	for _, name := range []string{
		"csharp-array", "nim-array", "go-bytes", "powershell-bytes",
		"vba-array", "vbs-array", "rust-array", "javascript-array", "zig-array",
	} {
		out := filepath.Join(dir, name+".txt")
		r := run(t, "", "encode", "--file", in, "--encoding", "hex",
			"--renderer", name, "--symbol", "payload", "--output", out, "--no-banner")
		if r.code != 0 {
			t.Fatalf("%s exit %d: %s", name, r.code, r.stderr)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(got, []byte("payload")) {
			t.Fatalf("%s output does not contain symbol:\n%s", name, got)
		}
	}
}

func TestEncryptRendersKeySourceRenderer(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{0x00, 0x01, 0x02, 0x03})
	keyHex := strings.Repeat("11", 32)
	r := run(t, "", "encrypt", "--file", in, "--key", keyHex,
		"--renderer", "javascript-array", "--symbol", "payload",
		"--key-symbol", "encryptionKey", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	out := string(r.stdout)
	if !strings.Contains(out, "const payload = new Uint8Array([") {
		t.Fatalf("missing data declaration:\n%s", out)
	}
	if !strings.Contains(out, "const encryptionKey = new Uint8Array([") {
		t.Fatalf("missing key declaration:\n%s", out)
	}
	got := hex.EncodeToString(jsArrayBytes(t, r.stdout, "const encryptionKey = new Uint8Array(["))
	if got != keyHex {
		t.Fatalf("rendered key = %s, want %s", got, keyHex)
	}
	if !strings.Contains(r.stderr, "key material is embedded in the output") {
		t.Fatalf("missing secret warning:\n%s", r.stderr)
	}
	if !strings.Contains(r.stderr, "included in output (32 bytes)") {
		t.Fatalf("missing key summary:\n%s", r.stderr)
	}
}

func TestEncryptPasswordDerivedKeyRendered(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	r := run(t, "", "encrypt", "--file", in, "--password", "1122",
		"--renderer", "javascript-array", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	key := jsArrayBytes(t, r.stdout, "const key = new Uint8Array([")
	if len(key) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(key))
	}
	if bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("derived key is all zeroes")
	}
}

func TestEncryptRenderedKeyMatchesDerivedKey(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	r := run(t, "", "encrypt", "--file", in, "--password", "1122",
		"--renderer", "javascript-array", "--symbol", "data",
		"--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}

	blob := jsArrayBytes(t, r.stdout, "const data = new Uint8Array([")
	key := jsArrayBytes(t, r.stdout, "const key = new Uint8Array([")
	parsed, err := container.Parse(blob, 1<<20)
	if err != nil {
		t.Fatalf("rendered container does not parse: %v", err)
	}
	derived, err := cryptography.DeriveKeySize([]byte("1122"), parsed.Header.Salt, len(key))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, key) {
		t.Fatalf("rendered key does not match the derived key")
	}
}

func TestAES128PasswordRoundTripAndKey(t *testing.T) {
	dir := t.TempDir()
	plain := []byte{0x00, 'A', 0xff, 'z'}
	in := writeFile(t, dir, "in.bin", plain)

	r := run(t, "", "encrypt", "--file", in, "--password", "1122",
		"--cipher", "aes-128-gcm", "--renderer", "javascript-array",
		"--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	if key := jsArrayBytes(t, r.stdout, "const key = new Uint8Array(["); len(key) != 16 {
		t.Fatalf("aes-128-gcm key length = %d, want 16", len(key))
	}

	container := filepath.Join(dir, "aes128.bf")
	r = run(t, "", "encrypt", "--file", in, "--password", "1122",
		"--cipher", "aes-128-gcm", "--output", container, "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	recovered := filepath.Join(dir, "recovered.bin")
	r = run(t, "", "decrypt", "--file", container, "--password", "1122",
		"--output", recovered, "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("decrypt exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("recovered = %x, want %x", got, plain)
	}
}

func TestEncryptJSONRendersKey(t *testing.T) {
	keyHex := strings.Repeat("11", 32)
	r := run(t, "", "encrypt", "--hex", "0001", "--key", keyHex,
		"--renderer", "json", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var doc struct {
		Data string `json:"data"`
		Key  struct {
			Symbol   string `json:"symbol"`
			Encoding string `json:"encoding"`
			Size     int    `json:"size"`
			Data     string `json:"data"`
		} `json:"key"`
	}
	if err := json.Unmarshal(r.stdout, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, r.stdout)
	}
	if doc.Key.Symbol != "key" || doc.Key.Encoding != "base64" || doc.Key.Size != 32 {
		t.Fatalf("key metadata = %+v", doc.Key)
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Key.Data)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != keyHex {
		t.Fatalf("rendered key = %x, want %s", raw, keyHex)
	}
}

func TestEncryptGeneratedKeyIsIncluded(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "payload.go")
	r := run(t, "", "encrypt", "--hex", "0001", "--renderer", "go-bytes",
		"--output", out, "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "var key = []byte{") {
		t.Fatalf("missing generated key declaration:\n%s", got)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestEncryptBareRendererOmitsKey(t *testing.T) {
	keyHex := strings.Repeat("11", 32)
	r := run(t, "", "encrypt", "--hex", "00", "--key", keyHex,
		"--renderer", "raw", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", r.code, r.stderr)
	}
	if _, err := container.Parse(r.stdout, 1<<20); err != nil {
		t.Fatalf("raw output is not just a container: %v", err)
	}
	if strings.Contains(r.stderr, "Key material") {
		t.Fatalf("raw output should not report an embedded key:\n%s", r.stderr)
	}
}

func TestEncryptRawGeneratedKeyRequiresExport(t *testing.T) {
	r := run(t, "", "encrypt", "--hex", "00", "--renderer", "raw", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "--export-key") {
		t.Fatalf("missing export guidance:\n%s", r.stderr)
	}
}

func TestEncryptKeySymbolConflict(t *testing.T) {
	r := run(t, "", "encrypt", "--hex", "00", "--key", strings.Repeat("11", 32),
		"--renderer", "go-bytes", "--symbol", "key", "--key-symbol", "key")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "must differ from --symbol") {
		t.Fatalf("missing symbol guidance:\n%s", r.stderr)
	}
}

func jsArrayBytes(t *testing.T, out []byte, start string) []byte {
	t.Helper()
	s := string(out)
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("missing %q in output:\n%s", start, s)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, "]);")
	if j < 0 {
		t.Fatalf("unterminated array after %q", start)
	}
	var hexText strings.Builder
	for _, m := range regexp.MustCompile(`0x([0-9A-Fa-f]{2})`).FindAllStringSubmatch(rest[:j], -1) {
		hexText.WriteString(m[1])
	}
	b, err := hex.DecodeString(hexText.String())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSummarySeparatedFromNonNewlinePayload(t *testing.T) {
	r := run(t, "", "encode", "--hex", "01020304", "--encoding", "ipv4-list",
		"--renderer", "raw", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.HasSuffix(string(r.stdout), "1.2.3.4") {
		t.Fatalf("unexpected payload: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "\n\n------------------------------------------------------------") {
		t.Fatalf("summary did not start after two newlines:\n%q", r.stderr)
	}
}

func TestSummaryNoExtraBlankAfterNewlinePayload(t *testing.T) {
	r := run(t, "", "encode", "--hex", "01020304", "--encoding", "raw",
		"--renderer", "hex", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if strings.Contains(r.stderr, "\n\n------------------------------------------------------------") {
		t.Fatalf("summary has an unexpected blank line:\n%q", r.stderr)
	}
}

func TestEncodePadUsesCodecWidth(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{0, 1, 2, 3, 4, 5, 6})
	r := run(t, "", "encode", "--file", in, "--encoding", "mac-list",
		"--pad", "zero", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	out := string(r.stdout)
	if !strings.Contains(out, "00:01:02:03:04:05") || !strings.Contains(out, "06:00:00:00:00:00") {
		t.Fatalf("padding did not reach the codec width:\n%s", out)
	}
	if !strings.Contains(r.stderr, "input 7 bytes padded by +5 bytes (zero/0x00) → total 12 bytes (2 chunks)") {
		t.Fatalf("missing padding diagnostic:\n%s", r.stderr)
	}
}

func TestEncodePadNoneRejectsMisalignment(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{0, 1, 2, 3, 4, 5, 6})
	r := run(t, "", "encode", "--file", in, "--encoding", "mac-list",
		"--pad", "none", "--no-banner", "--no-color")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "not a multiple of 6") || !strings.Contains(r.stderr, "--pad") {
		t.Fatalf("missing alignment guidance:\n%s", r.stderr)
	}
}

func TestEncodePadHexPatternOnListCodec(t *testing.T) {
	r := run(t, "", "encode", "--hex", "0001020304", "--encoding", "ipv4-list",
		"--renderer", "raw", "--pad", "9090", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got, want := string(r.stdout), "0.1.2.3\n4.144.144.144"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if !strings.Contains(r.stderr, "input 5 bytes padded by +3 bytes (hex/9090) → total 8 bytes (2 chunks)") {
		t.Fatalf("missing padding diagnostic:\n%s", r.stderr)
	}
}

func TestEncodeBarePadDefaultsToRandom(t *testing.T) {
	r := run(t, "", "encode", "--hex", "0001020304", "--encoding", "ipv4-list",
		"--renderer", "raw", "--pad", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got, want := strings.Count(string(r.stdout), "\n"), 1; got != want {
		t.Fatalf("line separators = %d, want %d; output=%q", got, want, r.stdout)
	}
	if !strings.Contains(r.stderr, "padded by +3 bytes (random) → total 8 bytes (2 chunks)") {
		t.Fatalf("missing random padding diagnostic:\n%s", r.stderr)
	}
}

func TestDecodePadAfterDecoding(t *testing.T) {
	r := run(t, "", "decode", "--hex", "303030313032", "--encoding", "hex",
		"--renderer", "raw", "--pad", "nop", "--pad-to", "4", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	want := []byte{0x00, 0x01, 0x02, 0x90}
	if !bytes.Equal(r.stdout, want) {
		t.Fatalf("output = %x, want %x", r.stdout, want)
	}
}

func TestEncryptPadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{1, 2, 3, 4, 5})
	containerPath := filepath.Join(dir, "padded.bf")
	r := run(t, "", "encrypt", "--file", in, "--password", "1122",
		"--pad", "zero", "--pad-to", "8", "--output", containerPath,
		"--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("encrypt exit %d: %s", r.code, r.stderr)
	}
	recovered := filepath.Join(dir, "recovered.bin")
	r = run(t, "", "decrypt", "--file", containerPath, "--password", "1122",
		"--output", recovered, "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("decrypt exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 2, 3, 4, 5, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("recovered = %x, want %x", got, want)
	}
}

func TestPadInvalidValueShowsChoices(t *testing.T) {
	r := run(t, "", "encode", "--hex", "00", "--encoding", "raw", "--pad", "xyz", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	for _, want := range []string{"none", "nop", "zero", "random", "CC", "9090"} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("padding hint missing %q:\n%s", want, r.stderr)
		}
	}
}

func TestPadToInvalidValueShowsRange(t *testing.T) {
	r := run(t, "", "encode", "--hex", "00", "--encoding", "raw", "--pad", "zero", "--pad-to", "0", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "between 1 and 1048576") {
		t.Fatalf("missing range guidance:\n%s", r.stderr)
	}
}

func TestEncodePadRejectsOversizedSingleValueCodec(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", bytes.Repeat([]byte{0xAB}, 276))
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv6",
		"--pad", "nop", "--no-banner", "--no-color")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	for _, want := range []string{
		"ipv6 requires exactly 16 bytes, got 276; --pad cannot truncate data.",
		"Use --encoding ipv6-list --pad nop to encode as a sequence of 18 addresses.",
	} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("missing %q in stderr:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "padded by") {
		t.Fatalf("padding ran before the codec rejected the input:\n%s", r.stderr)
	}
}

func TestEncodePadSingleValuePadsToExactWidth(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{1, 2})
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv4",
		"--pad", "zero", "--renderer", "raw", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got, want := string(r.stdout), "1.2.0.0"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestEncodePadEmptySingleValueFillsRequiredWidth(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "empty.bin", nil)
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv4",
		"--pad", "zero", "--renderer", "raw", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got, want := string(r.stdout), "0.0.0.0"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if !strings.Contains(r.stderr, "input 0 bytes padded by +4 bytes (zero/0x00) → total 4 bytes (1 chunk)") {
		t.Fatalf("missing padding diagnostic:\n%s", r.stderr)
	}
}

func TestEncodePadNonListIPv6FillsMissingTail(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{0x20, 0x01, 0x0d, 0xb8})
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv6",
		"--pad", "zero", "--renderer", "raw", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got, want := string(r.stdout), "2001:db8::"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
	if !strings.Contains(r.stderr, "input 4 bytes padded by +12 bytes (zero/0x00) → total 16 bytes (1 chunk)") {
		t.Fatalf("missing padding diagnostic:\n%s", r.stderr)
	}
}

func TestEncodePadRejectsIncompatiblePadToForSingleValue(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte{1, 2})
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv4",
		"--pad", "zero", "--pad-to", "8", "--no-banner", "--no-color")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "--pad-to 8 is incompatible with ipv4") {
		t.Fatalf("missing incompatibility guidance:\n%s", r.stderr)
	}
}

func TestEncodePadListAcceptsLongerPayload(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", bytes.Repeat([]byte{0xAB}, 276))
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv6-list",
		"--pad", "nop", "--renderer", "raw", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if got, want := strings.Count(string(r.stdout), "\n"), 17; got != want {
		t.Fatalf("line separators = %d, want %d", got, want)
	}
	if !strings.Contains(r.stderr, "input 276 bytes padded by +12 bytes (nop/0x90) → total 288 bytes (18 chunks)") {
		t.Fatalf("missing padding diagnostic:\n%s", r.stderr)
	}
}

func TestEncodePadIgnoredForNonFixedWidthCodec(t *testing.T) {
	plain := run(t, "", "encode", "--hex", "00010203", "--encoding", "base64",
		"--renderer", "raw", "--no-banner", "--no-color")
	padded := run(t, "", "encode", "--hex", "00010203", "--encoding", "base64",
		"--renderer", "raw", "--pad", "nop", "--no-banner", "--no-color")
	if padded.code != 0 {
		t.Fatalf("exit %d: %s", padded.code, padded.stderr)
	}
	if !bytes.Equal(plain.stdout, padded.stdout) {
		t.Fatalf("padding changed base64 output: %q vs %q", plain.stdout, padded.stdout)
	}
	if !strings.Contains(padded.stderr, "--pad has no effect for encoding 'base64'; ignoring") {
		t.Fatalf("missing ignore warning:\n%s", padded.stderr)
	}
	if strings.Contains(padded.stderr, "padded by") {
		t.Fatalf("padding unexpectedly applied:\n%s", padded.stderr)
	}
}

func TestEncodePadNoPaddingNeededList(t *testing.T) {
	r := run(t, "", "encode", "--hex", "0001020304050607", "--encoding", "ipv4-list",
		"--pad", "nop", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "no padding needed (8 bytes, 2 chunks)") {
		t.Fatalf("missing no-padding diagnostic:\n%s", r.stderr)
	}
}

func TestEncodePadNoPaddingNeededSingle(t *testing.T) {
	r := run(t, "", "encode", "--hex", "c0a80101", "--encoding", "ipv4",
		"--pad", "nop", "--no-banner", "--no-color")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "no padding needed") {
		t.Fatalf("missing no-padding diagnostic:\n%s", r.stderr)
	}
	if strings.Contains(r.stderr, "padded by") {
		t.Fatalf("padding unexpectedly applied:\n%s", r.stderr)
	}
}

func TestMissingFlagValueShowsChoices(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", []byte("payload"))
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "renderer",
			args: []string{"encrypt", "--file", in, "--password", "1122", "--renderer"},
			want: []string{"missing value for --renderer", "available renderers:", "csharp-array", "zig-array"},
		},
		{
			name: "encoding",
			args: []string{"encode", "--file", in, "--encoding"},
			want: []string{"missing value for --encoding", "available codecs:", "ipv4-list"},
		},
		{
			name: "cipher",
			args: []string{"encrypt", "--file", in, "--password", "1122", "--cipher"},
			want: []string{"missing value for --cipher", "available ciphers:", "aes-256-gcm", "rc4"},
		},
		{
			name: "transform",
			args: []string{"transform", "--file", in, "--transform"},
			want: []string{"missing value for --transform", "available transforms:", "xor-repeating-key"},
		},
		{
			name: "bytes-per-line",
			args: []string{"encode", "--file", in, "--encoding", "hex", "--bytes-per-line"},
			want: []string{"missing value for --bytes-per-line", "expected an integer from 1 to 256"},
		},
		{
			name: "max-input",
			args: []string{"encode", "--file", in, "--encoding", "hex", "--max-input"},
			want: []string{"missing value for --max-input", "expected a positive byte count"},
		},
		{
			name: "output",
			args: []string{"encode", "--file", in, "--encoding", "hex", "--output"},
			want: []string{"missing value for --output", "expected a file path"},
		},
		{
			name: "short output",
			args: []string{"encode", "--file", in, "--encoding", "hex", "-o"},
			want: []string{"missing value for -o", "expected a file path"},
		},
		{
			name: "password",
			args: []string{"encrypt", "--file", in, "--password"},
			want: []string{"missing value for --password", "expected a password string"},
		},
		{
			name: "sha256",
			args: []string{"verify", "--file", in, "--sha256"},
			want: []string{"missing value for --sha256", "expected a 64-character hexadecimal SHA-256 digest"},
		},
		{
			name: "key-symbol",
			args: []string{"encrypt", "--hex", "00", "--key-symbol"},
			want: []string{"missing value for --key-symbol", "expected an identifier"},
		},
		{
			name: "invalid integer",
			args: []string{"encode", "--file", in, "--encoding", "hex", "--bytes-per-line", "abc"},
			want: []string{`invalid value "abc" for --bytes-per-line`, "expected an integer from 1 to 256"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, "", tc.args...)
			if r.code != 2 {
				t.Fatalf("exit = %d, want 2; stderr=%s", r.code, r.stderr)
			}
			for _, want := range tc.want {
				if !strings.Contains(r.stderr, want) {
					t.Fatalf("stderr missing %q:\n%s", want, r.stderr)
				}
			}
		})
	}
}

func TestHexInputAndAliases(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.bin")
	r := run(t, "", "encode", "-s", "0x48656c6c6f", "--encoding", "raw", "-o", out, "--no-banner")
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "Hello" {
		t.Fatalf("got %q", got)
	}
}

func TestTransformRoundTrip(t *testing.T) {
	dir := t.TempDir()
	input := []byte("transform me")
	in := writeFile(t, dir, "in.bin", input)
	transformed := filepath.Join(dir, "t.bin")
	restored := filepath.Join(dir, "r.bin")

	r := run(t, "", "transform", "--file", in, "--transform", "xor-repeating-key", "--key", "deadbeef", "--output", transformed, "--no-banner")
	if r.code != 0 {
		t.Fatalf("transform exit %d: %s", r.code, r.stderr)
	}
	r = run(t, "", "untransform", "--file", transformed, "--transform", "xor-repeating-key", "--key", "deadbeef", "--output", restored, "--no-banner")
	if r.code != 0 {
		t.Fatalf("untransform exit %d: %s", r.code, r.stderr)
	}
	got, _ := os.ReadFile(restored)
	if !bytes.Equal(got, input) {
		t.Fatal("transform round trip failed")
	}
}

func TestTypedListSequence(t *testing.T) {
	dir := t.TempDir()
	input := make([]byte, 276) // 69 IPv4 values
	for i := range input {
		input[i] = byte(i)
	}
	in := writeFile(t, dir, "calc.bin", input)
	encoded := filepath.Join(dir, "addresses.txt")
	recovered := filepath.Join(dir, "recovered.bin")

	r := run(t, "", "encode", "--file", in, "--encoding", "ipv4-list", "--output", encoded, "--no-banner")
	if r.code != 0 {
		t.Fatalf("encode exit %d: %s", r.code, r.stderr)
	}
	text, err := os.ReadFile(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(text, []byte("\n")); got != 68 {
		t.Fatalf("encoded %d newlines, want 68 (69 addresses)", got)
	}

	r = run(t, "", "decode", "--file", encoded, "--encoding", "ipv4-list", "--output", recovered, "--no-banner")
	if r.code != 0 {
		t.Fatalf("decode exit %d: %s", r.code, r.stderr)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("ipv4-list round trip failed")
	}
}

func TestFixedWidthHint(t *testing.T) {
	dir := t.TempDir()
	in := writeFile(t, dir, "in.bin", make([]byte, 8))
	r := run(t, "", "encode", "--file", in, "--encoding", "ipv4", "--no-banner")
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2", r.code)
	}
	if !strings.Contains(r.stderr, "ipv4-list") {
		t.Fatalf("error does not suggest ipv4-list: %s", r.stderr)
	}
}
