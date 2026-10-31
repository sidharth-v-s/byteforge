package codec

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/registry"
)

// typedListCodec represents a sequence of fixed-width typed values. It is
// lossless: every input byte belongs to exactly one value and the encoded form
// does not invent padding. Short inputs are rejected rather than padded,
// because removing padding on decode would be ambiguous for arbitrary binary
// data.
type typedListCodec struct {
	name   string
	desc   string
	elem   registry.Codec
	width  int
	input  string
	output string
}

func init() {
	Register(&typedListCodec{
		name:   "mac-list",
		desc:   "Newline-separated EUI-48/MAC addresses (lossless sequence)",
		elem:   macCodec{},
		width:  6,
		input:  "length must be a multiple of 6 bytes",
		output: "one MAC address per line",
	})
	Register(&typedListCodec{
		name:   "ipv4-list",
		desc:   "Newline-separated IPv4 addresses (lossless sequence)",
		elem:   ipv4Codec{},
		width:  4,
		input:  "length must be a multiple of 4 bytes",
		output: "one IPv4 address per line",
	})
	Register(&typedListCodec{
		name:   "ipv6-list",
		desc:   "Newline-separated IPv6 addresses (lossless sequence)",
		elem:   ipv6Codec{},
		width:  16,
		input:  "length must be a multiple of 16 bytes",
		output: "one IPv6 address per line",
	})
	Register(&typedListCodec{
		name:   "uuid-list",
		desc:   "Newline-separated RFC 4122 UUIDs (lossless sequence)",
		elem:   uuidCodec{},
		width:  16,
		input:  "length must be a multiple of 16 bytes",
		output: "one UUID per line",
	})
}

// Width reports the fixed element width used for explicit padding targets.
func (c *typedListCodec) Width() int { return c.width }

func (c *typedListCodec) Info() registry.Info {
	return registry.Info{
		Name:        c.name,
		Description: c.desc,
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       c.input,
		Output:      c.output,
		Parameters: []string{
			fmt.Sprintf("input length must be a multiple of %d bytes", c.width),
			"encode: one value per line",
			"decode: whitespace, comma, or semicolon between values",
			"no implicit padding; empty input is preserved",
		},
	}
}

func (c *typedListCodec) Encode(data []byte) ([]byte, error) {
	if len(data)%c.width != 0 {
		return nil, bferrors.New(bferrors.Usage,
			"%s requires a multiple of %d bytes, got %d (%d-byte remainder)",
			c.name, c.width, len(data), len(data)%c.width)
	}
	if len(data) == 0 {
		return []byte{}, nil
	}

	var b strings.Builder
	for i := 0; i < len(data); i += c.width {
		enc, err := c.elem.Encode(data[i : i+c.width])
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.Write(enc)
	}
	return []byte(b.String()), nil
}

func (c *typedListCodec) Decode(data []byte) ([]byte, error) {
	s := string(data)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';'
	})
	if len(fields) == 0 {
		return []byte{}, nil
	}

	out := make([]byte, 0, len(fields)*c.width)
	for i, field := range fields {
		dec, err := c.elem.Decode([]byte(field))
		if err != nil {
			return nil, bferrors.Wrap(bferrors.Processing, err, "%s: value %d", c.name, i+1)
		}
		if len(dec) != c.width {
			return nil, bferrors.New(bferrors.Processing,
				"%s: value %d decoded to %d bytes, want %d", c.name, i+1, len(dec), c.width)
		}
		out = append(out, dec...)
	}
	return out, nil
}

// listCodecFor returns the sequence codec corresponding to a fixed-width
// single-value codec, if one exists.
func listCodecFor(name string) string {
	switch name {
	case "mac":
		return "mac-list"
	case "ipv4":
		return "ipv4-list"
	case "ipv6":
		return "ipv6-list"
	case "uuid":
		return "uuid-list"
	default:
		return ""
	}
}
