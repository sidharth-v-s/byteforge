package renderer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/zoro/byteforge/internal/registry"
)

func meta(op string) registry.Meta {
	return registry.Meta{
		Tool:         "byteforge",
		Version:      "test",
		Operation:    op,
		Format:       "hex",
		InputSize:    4,
		InputSHA256:  "00",
		Verification: "PASSED",
		Symbol:       "payload",
		BytesPerLine: 8,
	}
}

func TestRawIdentity(t *testing.T) {
	r, _ := Get("raw")
	data := []byte{0x00, 0xff, 0x10, 0x00}
	got, err := r.Render(data, meta("encode"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("raw renderer changed bytes")
	}
}

func TestHexRenderer(t *testing.T) {
	r, _ := Get("hex")
	got, err := r.Render([]byte{0xde, 0xad, 0xbe, 0xef}, meta("encode"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "DEADBEEF\n" {
		t.Fatalf("got %q", got)
	}
}

func TestBase64Renderer(t *testing.T) {
	r, _ := Get("base64")
	got, err := r.Render([]byte("Hello"), meta("encode"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "SGVsbG8=\n" {
		t.Fatalf("got %q", got)
	}
}

func TestCArray(t *testing.T) {
	r, _ := Get("c-array")
	data := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	got, err := r.Render(data, meta("encrypt"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, "unsigned char payload[] = {") {
		t.Fatalf("missing declaration:\n%s", s)
	}
	if strings.Count(s, "0x") != len(data) {
		t.Fatalf("expected %d byte literals:\n%s", len(data), s)
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 2 comments, declaration, 2 data lines, and closing brace; got %d lines:\n%s", len(lines), s)
	}
	for _, forbidden := range []string{"malloc", "VirtualAlloc", "CreateThread", "system(", "exec"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("c-array contains forbidden executable construct %q", forbidden)
		}
	}
}

func TestCArraySymbolValidation(t *testing.T) {
	r, _ := Get("c-array")
	for _, bad := range []string{"1abc", "a-b", "a b", "a;b"} {
		m := meta("encode")
		m.Symbol = bad
		if _, err := r.Render([]byte{1}, m); err == nil {
			t.Fatalf("accepted symbol %q", bad)
		}
	}
	m := meta("encode")
	m.Symbol = "_valid123"
	if _, err := r.Render([]byte{1}, m); err != nil {
		t.Fatalf("rejected valid symbol: %v", err)
	}
}

func TestCArrayBytesPerLine(t *testing.T) {
	r, _ := Get("c-array")
	m := meta("encode")
	m.BytesPerLine = 4
	got, err := r.Render([]byte{1, 2, 3, 4, 5}, m)
	if err != nil {
		t.Fatal(err)
	}
	dataLines := 0
	for _, line := range strings.Split(string(got), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "0x") {
			dataLines++
		}
	}
	if dataLines != 2 {
		t.Fatalf("expected 2 data lines, got %d:\n%s", dataLines, got)
	}
	m.BytesPerLine = -1
	if _, err := r.Render([]byte{1}, m); err == nil {
		t.Fatal("accepted negative bytes-per-line")
	}
}

func TestCArrayEmpty(t *testing.T) {
	r, _ := Get("c-array")
	got, err := r.Render(nil, meta("encode"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "placeholder: input was empty") {
		t.Fatalf("empty c-array lacks placeholder:\n%s", got)
	}
}

func TestPythonBytes(t *testing.T) {
	r, _ := Get("python-bytes")
	got, err := r.Render([]byte{0x00, 0x41, 0xff}, meta("encode"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	if !strings.Contains(s, `payload = (`) {
		t.Fatalf("missing assignment:\n%s", s)
	}
	if !strings.Contains(s, `b"\x00\x41\xff"`) {
		t.Fatalf("missing escaped bytes:\n%s", s)
	}
	if strings.Contains(s, "exec(") || strings.Contains(s, "import os") {
		t.Fatal("python output contains executable code")
	}
	empty, err := r.Render(nil, meta("encode"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty), `payload = b""`) {
		t.Fatalf("empty python literal wrong:\n%s", empty)
	}
}

func TestPythonIdentifierValidation(t *testing.T) {
	r, _ := Get("python-bytes")
	for _, bad := range []string{"1abc", "a-b", "a b"} {
		m := meta("encode")
		m.Symbol = bad
		if _, err := r.Render([]byte{1}, m); err == nil {
			t.Fatalf("accepted Python identifier %q", bad)
		}
	}
}

func TestJSONRenderer(t *testing.T) {
	r, _ := Get("json")
	data := []byte{0x00, 0x01, 0x02, 0xff}
	got, err := r.Render(data, meta("encrypt"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, got)
	}
	if doc["schemaVersion"] != "1.0" {
		t.Fatalf("schemaVersion = %v", doc["schemaVersion"])
	}
	if doc["operation"] != "encrypt" {
		t.Fatalf("operation = %v", doc["operation"])
	}
	if doc["dataEncoding"] != "base64" {
		t.Fatalf("dataEncoding = %v", doc["dataEncoding"])
	}
	decoded, err := base64.StdEncoding.DecodeString(doc["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("JSON data does not round trip")
	}
	if doc["verification"] != "passed" {
		t.Fatalf("verification = %v", doc["verification"])
	}
}

func TestRegistryMetadata(t *testing.T) {
	for _, name := range Names() {
		r, ok := Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if r.Info().Name != name || r.Info().Description == "" {
			t.Fatalf("bad metadata for %s", name)
		}
		if r.Info().Security != registry.SecurityRenderer {
			t.Fatalf("%s security = %q", name, r.Info().Security)
		}
	}
}

func TestNoAnsiInRenderedData(t *testing.T) {
	// Renderers must not inject terminal escape sequences into payload data.
	ansi := regexp.MustCompile("\x1b\\[")
	for _, name := range Names() {
		r, _ := Get(name)
		out, err := r.Render([]byte("payload"), meta("encode"))
		if err != nil {
			t.Fatal(err)
		}
		if ansi.Match(out) {
			t.Fatalf("%s emitted ANSI escapes", name)
		}
	}
}
