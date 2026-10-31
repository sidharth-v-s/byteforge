package renderer

import (
	"strings"
	"testing"
)

func TestLanguageRenderers(t *testing.T) {
	data := []byte{0x00, 0x41, 0xFF}
	cases := []struct {
		name    string
		decl    string
		literal string
		empty   string
	}{
		{"csharp-array", "byte[] payload = new byte[] {", "0x00, 0x41, 0xFF,", "new byte[0]"},
		{"nim-array", "const payload: array[3, byte] = [", "0x00'u8, 0x41'u8, 0xFF'u8", "array[0, byte] = []"},
		{"go-bytes", "var payload = []byte{", "0x00, 0x41, 0xFF,", "[]byte{}"},
		{"powershell-bytes", "[byte[]] $payload = @(", "0x00, 0x41, 0xFF", "@()"},
		{"vba-array", "Dim payload(0 To 2) As Byte", "payload(0) = 0", "Dim payload() As Byte"},
		{"vbs-array", "payload = Array(0, 65, 255)", "payload = Array(0, 65, 255)", "payload = Array()"},
		{"rust-array", "pub static payload: [u8; 3] = [", "0x00, 0x41, 0xFF,", "[u8; 0] = []"},
		{"javascript-array", "const payload = new Uint8Array([", "0x00, 0x41, 0xFF,", "new Uint8Array([])"},
		{"zig-array", "pub const payload = [_]u8{", "0x00, 0x41, 0xFF,", "[_]u8{}"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r, ok := Get(tc.name)
			if !ok {
				t.Fatalf("%s is not registered", tc.name)
			}
			out, err := r.Render(data, meta("encrypt"))
			if err != nil {
				t.Fatal(err)
			}
			s := string(out)
			if !strings.Contains(s, tc.decl) {
				t.Fatalf("missing declaration %q:\n%s", tc.decl, s)
			}
			if !strings.Contains(s, tc.literal) {
				t.Fatalf("missing byte literal %q:\n%s", tc.literal, s)
			}
			if !strings.Contains(s, "data declaration only") {
				t.Fatalf("missing data-only header:\n%s", s)
			}

			empty, err := r.Render(nil, meta("encode"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(empty), tc.empty) {
				t.Fatalf("empty output missing %q:\n%s", tc.empty, empty)
			}
		})
	}
}

func TestLanguageRenderersRejectInvalidSymbols(t *testing.T) {
	for _, name := range []string{
		"csharp-array", "nim-array", "go-bytes", "powershell-bytes",
		"vba-array", "vbs-array", "rust-array", "javascript-array", "zig-array",
	} {
		r, _ := Get(name)
		for _, bad := range []string{"1abc", "a-b", "a b", "a;b", "$"} {
			m := meta("encode")
			m.Symbol = bad
			if _, err := r.Render([]byte{1}, m); err == nil {
				t.Fatalf("%s accepted symbol %q", name, bad)
			}
		}
		m := meta("encode")
		m.Symbol = "_valid123"
		if _, err := r.Render([]byte{1}, m); err != nil {
			t.Fatalf("%s rejected valid symbol: %v", name, err)
		}
	}
}

func TestPowerShellOptionalDollar(t *testing.T) {
	r, _ := Get("powershell-bytes")
	m := meta("encode")
	m.Symbol = "$payload"
	out, err := r.Render([]byte{1}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "[byte[]] $payload = @(") {
		t.Fatalf("missing variable declaration:\n%s", out)
	}
	if strings.Contains(string(out), "$$") {
		t.Fatalf("duplicated dollar sign:\n%s", out)
	}
}

func TestLanguageRenderersBytesPerLine(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	m := meta("encode")
	m.BytesPerLine = 2

	vba, _ := Get("vba-array")
	out, err := vba.Render(data, m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "payload(0) = 1: payload(1) = 2") {
		t.Fatalf("VBA did not group assignments:\n%s", out)
	}

	vbs, _ := Get("vbs-array")
	out, err = vbs.Render(data, m)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "payload = Array( _") {
		t.Fatalf("VBS missing continuation:\n%s", s)
	}
	if !strings.Contains(s, "1, 2, _") || !strings.Contains(s, "5)") {
		t.Fatalf("VBS did not group values:\n%s", s)
	}

	for _, name := range []string{"csharp-array", "nim-array", "go-bytes", "powershell-bytes", "rust-array", "javascript-array", "zig-array"} {
		r, _ := Get(name)
		out, err := r.Render(data, m)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings.Count(string(out), "0x"); got != len(data) {
			t.Fatalf("%s emitted %d literals, want %d:\n%s", name, got, len(data), out)
		}
	}
}

func TestLanguageRenderersNoLoaderConstructs(t *testing.T) {
	forbidden := []string{
		"malloc", "VirtualAlloc", "CreateThread", "system(",
		"exec(", "import os", "os.system", "unsafe", "LoadLibrary",
	}
	for _, name := range []string{
		"csharp-array", "nim-array", "go-bytes", "powershell-bytes",
		"vba-array", "vbs-array", "rust-array", "javascript-array", "zig-array",
	} {
		r, _ := Get(name)
		out, err := r.Render([]byte("payload"), meta("encrypt"))
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if strings.Contains(string(out), bad) {
				t.Fatalf("%s contains forbidden construct %q:\n%s", name, bad, out)
			}
		}
	}
}
