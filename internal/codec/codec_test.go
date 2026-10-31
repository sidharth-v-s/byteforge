package codec

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func allBytes() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestVariableLengthRoundTrip(t *testing.T) {
	payloads := map[string][]byte{
		"empty":        {},
		"one zero":     {0x00},
		"one high":     {0xff},
		"text":         []byte("Hello, ByteForge!"),
		"nulls":        {0, 0, 0, 0},
		"all 256":      allBytes(),
		"high entropy": {0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x80, 0xff},
	}
	names := []string{"hex", "base64", "base64url", "base32", "ascii85", "raw", "decimal", "octal", "binary", "c-escaped", "unicode-escape"}
	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			c, ok := Get(name)
			if !ok {
				t.Fatalf("codec %s is not registered", name)
			}
			for label, payload := range payloads {
				encoded, err := c.Encode(payload)
				if err != nil {
					t.Fatalf("%s/%s encode: %v", name, label, err)
				}
				decoded, err := c.Decode(encoded)
				if err != nil {
					t.Fatalf("%s/%s decode: %v", name, label, err)
				}
				if !bytes.Equal(decoded, payload) {
					t.Fatalf("%s/%s round trip mismatch: got %x want %x", name, label, decoded, payload)
				}
			}
		})
	}
}

func TestFixedLengthRoundTrip(t *testing.T) {
	cases := map[string][]byte{
		"mac":  {0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc},
		"ipv4": {192, 168, 1, 10},
		"ipv6": {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		"uuid": {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	for name, payload := range cases {
		c, ok := Get(name)
		if !ok {
			t.Fatalf("codec %s is not registered", name)
		}
		encoded, err := c.Encode(payload)
		if err != nil {
			t.Fatalf("%s encode: %v", name, err)
		}
		decoded, err := c.Decode(encoded)
		if err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("%s round trip mismatch: got %x want %x", name, decoded, payload)
		}
	}
}

func TestKnownVectors(t *testing.T) {
	tests := []struct {
		codec  string
		input  []byte
		output string
	}{
		{"hex", []byte("Hello"), "48656C6C6F"},
		{"base64", []byte("Hello"), "SGVsbG8="},
		{"base64url", []byte{0xfb, 0xff}, "-_8="},
		{"base32", []byte("Hello"), "JBSWY3DP"},
		{"mac", []byte{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc}, "00:11:22:AA:BB:CC"},
		{"ipv4", []byte{192, 168, 1, 10}, "192.168.1.10"},
		{"ipv6", []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::1"},
		{"uuid", []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, "00112233-4455-6677-8899-aabbccddeeff"},
		{"decimal", []byte{0, 1, 255}, "0 1 255"},
		{"octal", []byte{0, 1, 255}, "000 001 377"},
		{"binary", []byte{0x0f, 0xf0}, "00001111 11110000"},
	}
	for _, tc := range tests {
		c, ok := Get(tc.codec)
		if !ok {
			t.Fatalf("codec %s is not registered", tc.codec)
		}
		got, err := c.Encode(tc.input)
		if err != nil {
			t.Fatalf("%s encode: %v", tc.codec, err)
		}
		if string(got) != tc.output {
			t.Fatalf("%s Encode(%x) = %q, want %q", tc.codec, tc.input, got, tc.output)
		}
	}
}

func TestUUIDDecodeRejectsVariants(t *testing.T) {
	c, _ := Get("uuid")
	bad := []string{
		"00112233445566778899aabbccddeeff",
		"{00112233-4455-6677-8899-aabbccddeeff}",
		"00112233-4455-6677-8899-aabbccddeef",
		"00112233-4455-6677-8899-aabbccddeefg",
		"00112233-4455-6677-8899-aabbccddeeff-",
	}
	for _, s := range bad {
		if _, err := c.Decode([]byte(s)); err == nil {
			t.Fatalf("uuid accepted invalid form %q", s)
		}
	}
}

func TestTypedLengthRejection(t *testing.T) {
	cases := []struct {
		codec string
		data  []byte
	}{
		{"mac", make([]byte, 5)},
		{"mac", make([]byte, 7)},
		{"ipv4", make([]byte, 3)},
		{"ipv4", make([]byte, 16)},
		{"ipv6", make([]byte, 4)},
		{"ipv6", make([]byte, 15)},
		{"uuid", make([]byte, 15)},
		{"uuid", make([]byte, 17)},
	}
	for _, tc := range cases {
		c, _ := Get(tc.codec)
		if _, err := c.Encode(tc.data); err == nil {
			t.Fatalf("%s accepted %d-byte input", tc.codec, len(tc.data))
		}
	}
}

func TestInvalidInputs(t *testing.T) {
	cases := []struct {
		codec string
		input string
	}{
		{"hex", "abc"},
		{"hex", "zz"},
		{"base64", "!!!!"},
		{"base64", "SGVsbG8"},   // missing padding
		{"base64url", "++//"},   // standard alphabet not allowed
		{"base32", "JBSWY3DP1"}, // invalid length/alphabet
		{"mac", "00:11:22:33:44"},
		{"mac", "00:11:22:33:44:55:66"},
		{"ipv4", "999.1.1.1"},
		{"ipv4", "::1"},
		{"ipv6", "1.2.3.4"},
		{"ipv6", "gggg::1"},
		{"decimal", "256"},
		{"decimal", "-1"},
		{"octal", "400"},
		{"octal", "8"},
		{"binary", "1010101"},
		{"binary", "101010102"},
		{"c-escaped", "abc"},
		{"c-escaped", `"\q"`},
		{"c-escaped", `"\x1"`},
		{"unicode-escape", `\u0100`},
		{"unicode-escape", `\u00zz`},
	}
	for _, tc := range cases {
		c, _ := Get(tc.codec)
		if _, err := c.Decode([]byte(tc.input)); err == nil {
			t.Fatalf("%s accepted invalid input %q", tc.codec, tc.input)
		}
	}
}

func TestHexAcceptsSeparators(t *testing.T) {
	c, _ := Get("hex")
	got, err := c.Decode([]byte("0x48 65:6c-6c_6f\\x21"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "Hello!" {
		t.Fatalf("got %q", got)
	}
}

func TestHexEncodeUppercase(t *testing.T) {
	c, _ := Get("hex")
	got, _ := c.Encode([]byte{0xde, 0xad, 0xbe, 0xef})
	if string(got) != "DEADBEEF" {
		t.Fatalf("got %q", got)
	}
	if got[0] != 'D' {
		t.Fatalf("expected uppercase hex, got %q", got)
	}
}

func TestBase32CaseInsensitiveDecode(t *testing.T) {
	c, _ := Get("base32")
	got, err := c.Decode([]byte(strings.ToLower("JBSWY3DP")))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "Hello" {
		t.Fatalf("got %q", got)
	}
}

func TestRegistryMetadata(t *testing.T) {
	for _, name := range Names() {
		c, ok := Get(name)
		if !ok {
			t.Fatalf("missing %s", name)
		}
		info := c.Info()
		if info.Name != name {
			t.Fatalf("info name %q does not match registry key %q", info.Name, name)
		}
		if info.Description == "" {
			t.Fatalf("%s has no description", name)
		}
		if info.Security != "representation" {
			t.Fatalf("%s has unexpected security class %q", name, info.Security)
		}
	}
}

func TestHexVectorSanity(t *testing.T) {
	sum, _ := hex.DecodeString("48656c6c6f")
	if string(sum) != "Hello" {
		t.Fatal("test setup is broken")
	}
}
