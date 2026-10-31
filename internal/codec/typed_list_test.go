package codec

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTypedListRoundTripAndVectors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "mac-list",
			input: "001122aabbccdeadbeef0001",
			want:  "00:11:22:AA:BB:CC\nDE:AD:BE:EF:00:01",
		},
		{
			name:  "ipv4-list",
			input: "c0a8010108080808",
			want:  "192.168.1.1\n8.8.8.8",
		},
		{
			name:  "ipv6-list",
			input: "20010db800000000000000000000000100000000000000000000000000000001",
			want:  "2001:db8::1\n::1",
		},
		{
			name:  "uuid-list",
			input: "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100",
			want:  "00112233-4455-6677-8899-aabbccddeeff\nffeeddcc-bbaa-9988-7766-554433221100",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c, ok := Get(tc.name)
			if !ok {
				t.Fatalf("%s is not registered", tc.name)
			}
			input, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Encode(input)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("Encode = %q, want %q", got, tc.want)
			}
			back, err := c.Decode(got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, input) {
				t.Fatalf("round trip = %x, want %x", back, input)
			}
		})
	}
}

func TestTypedListDecodeSeparators(t *testing.T) {
	c, _ := Get("ipv4-list")
	want, _ := hex.DecodeString("c0a8010108080808")
	for _, input := range []string{
		"192.168.1.1 8.8.8.8",
		"192.168.1.1,8.8.8.8",
		"192.168.1.1; 8.8.8.8",
		"192.168.1.1\r\n8.8.8.8\r\n",
		"\n 192.168.1.1 \n\n 8.8.8.8 \n",
	} {
		got, err := c.Decode([]byte(input))
		if err != nil {
			t.Fatalf("Decode(%q): %v", input, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("Decode(%q) = %x, want %x", input, got, want)
		}
	}
}

func TestTypedListEmptyInput(t *testing.T) {
	for _, name := range []string{"mac-list", "ipv4-list", "ipv6-list", "uuid-list"} {
		c, _ := Get(name)
		got, err := c.Encode(nil)
		if err != nil {
			t.Fatalf("%s Encode(nil): %v", name, err)
		}
		if len(got) != 0 {
			t.Fatalf("%s Encode(nil) = %q", name, got)
		}
		back, err := c.Decode([]byte(" \n\t"))
		if err != nil {
			t.Fatalf("%s Decode(blank): %v", name, err)
		}
		if len(back) != 0 {
			t.Fatalf("%s Decode(blank) = %x", name, back)
		}
	}
}

func TestCodecWidths(t *testing.T) {
	fixed := map[string]int{
		"mac-list":  6,
		"ipv4-list": 4,
		"ipv6-list": 16,
		"uuid-list": 16,
	}
	for name, want := range fixed {
		got, ok := FixedWidth(name)
		if !ok || got != want {
			t.Fatalf("FixedWidth(%q) = %d, %v; want %d, true", name, got, ok, want)
		}
	}
	exact := map[string]int{
		"mac":  6,
		"ipv4": 4,
		"ipv6": 16,
		"uuid": 16,
	}
	for name, want := range exact {
		got, ok := ExactWidth(name)
		if !ok || got != want {
			t.Fatalf("ExactWidth(%q) = %d, %v; want %d, true", name, got, ok, want)
		}
		if list := ListCodec(name); list != name+"-list" {
			t.Fatalf("ListCodec(%q) = %q", name, list)
		}
	}
	for _, name := range []string{"hex", "base64", "raw", "decimal"} {
		if _, ok := FixedWidth(name); ok {
			t.Fatalf("FixedWidth(%q) unexpectedly reports a width", name)
		}
		if _, ok := ExactWidth(name); ok {
			t.Fatalf("ExactWidth(%q) unexpectedly reports a width", name)
		}
		if list := ListCodec(name); list != "" {
			t.Fatalf("ListCodec(%q) = %q", name, list)
		}
	}
}

func TestTypedListRejectsNonMultipleLengths(t *testing.T) {
	widths := map[string]int{
		"mac-list":  6,
		"ipv4-list": 4,
		"ipv6-list": 16,
		"uuid-list": 16,
	}
	for name, width := range widths {
		c, _ := Get(name)
		for _, n := range []int{1, width - 1, width + 1, width*2 + 1} {
			if n <= 0 {
				continue
			}
			if _, err := c.Encode(make([]byte, n)); err == nil {
				t.Fatalf("%s accepted %d bytes (width %d)", name, n, width)
			}
		}
	}
}

func TestTypedListRejectsMalformedValues(t *testing.T) {
	cases := map[string]string{
		"mac-list":  "00:11:22:33:44",
		"ipv4-list": "999.1.1.1",
		"ipv6-list": "1.2.3.4",
		"uuid-list": "not-a-uuid",
	}
	for name, input := range cases {
		c, _ := Get(name)
		if _, err := c.Decode([]byte(input)); err == nil {
			t.Fatalf("%s accepted %q", name, input)
		}
	}
}

func TestSingleCodecLengthHint(t *testing.T) {
	cases := []struct {
		codec  string
		length int
		hint   string
	}{
		{"mac", 7, "mac-list"},
		{"ipv4", 8, "ipv4-list"},
		{"ipv6", 17, "ipv6-list"},
		{"uuid", 17, "uuid-list"},
	}
	for _, tc := range cases {
		c, _ := Get(tc.codec)
		_, err := c.Encode(make([]byte, tc.length))
		if err == nil {
			t.Fatalf("%s accepted %d bytes", tc.codec, tc.length)
		}
		if !strings.Contains(err.Error(), tc.hint) {
			t.Fatalf("%s error %q does not mention %s", tc.codec, err, tc.hint)
		}
	}
}
