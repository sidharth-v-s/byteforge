package codec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestPublishedVectors checks testdata/codecs.json against the live registry.
// The vectors are documented in docs/FORMATS.md.
func TestPublishedVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "codecs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name       string `json:"name"`
		InputHex   string `json:"inputHex"`
		Encoded    string `json:"encoded"`
		EncodedHex string `json:"encodedHex"`
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no codec vectors")
	}
	for _, v := range vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			c, ok := Get(v.Name)
			if !ok {
				t.Fatalf("codec %s is not registered", v.Name)
			}
			input, err := hex.DecodeString(v.InputHex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := c.Encode(input)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(v.EncodedHex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Encode(%s) = %x, want %x", v.InputHex, got, want)
			}
			if v.Encoded != "" && string(got) != v.Encoded {
				t.Fatalf("Encode(%s) = %q, want %q", v.InputHex, got, v.Encoded)
			}
			decoded, err := c.Decode(want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, input) {
				t.Fatalf("Decode(%x) = %x, want %x", want, decoded, input)
			}
		})
	}
}
