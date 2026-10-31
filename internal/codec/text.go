package codec

import (
	"bytes"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/bytesutil"
	"github.com/zoro/byteforge/internal/registry"
)

func init() {
	Register(hexCodec{})
	Register(base64Codec{})
	Register(base64URLCodec{})
	Register(base32Codec{})
	Register(ascii85Codec{})
	Register(rawCodec{})
}

// ---------------------------------------------------------------- hex

type hexCodec struct{}

func (hexCodec) Info() registry.Info {
	return registry.Info{
		Name:        "hex",
		Description: "Strict hexadecimal text (uppercase output)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "hex text",
		Parameters:  []string{"decode accepts whitespace, ':', '-', ',', '_' and 0x/\\x prefixes"},
	}
}

func (hexCodec) Encode(data []byte) ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(data)))
	hex.Encode(out, data)
	return bytes.ToUpper(out), nil
}

func (hexCodec) Decode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	out, err := bytesutil.ParseHex(string(data))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid hex input")
	}
	return out, nil
}

// ---------------------------------------------------------------- base64

type base64Codec struct{}

func (base64Codec) Info() registry.Info {
	return registry.Info{
		Name:        "base64",
		Description: "Standard Base64 with padding (RFC 4648 §4)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "Base64 text",
		Parameters:  []string{"decode ignores ASCII whitespace", "strict padding"},
	}
}

func (base64Codec) Encode(data []byte) ([]byte, error) {
	out := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(out, data)
	return out, nil
}

func (base64Codec) Decode(data []byte) ([]byte, error) {
	clean := stripWhitespace(data)
	out, err := base64.StdEncoding.Strict().DecodeString(string(clean))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid base64 input")
	}
	return out, nil
}

// ---------------------------------------------------------------- base64url

type base64URLCodec struct{}

func (base64URLCodec) Info() registry.Info {
	return registry.Info{
		Name:        "base64url",
		Description: "URL-safe Base64 with padding (RFC 4648 §5)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "Base64url text",
		Parameters:  []string{"decode ignores ASCII whitespace", "strict padding"},
	}
}

func (base64URLCodec) Encode(data []byte) ([]byte, error) {
	out := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
	base64.URLEncoding.Encode(out, data)
	return out, nil
}

func (base64URLCodec) Decode(data []byte) ([]byte, error) {
	clean := stripWhitespace(data)
	out, err := base64.URLEncoding.Strict().DecodeString(string(clean))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid base64url input")
	}
	return out, nil
}

// ---------------------------------------------------------------- base32

var base32Encoding = base32.StdEncoding.WithPadding(base32.StdPadding)

type base32Codec struct{}

func (base32Codec) Info() registry.Info {
	return registry.Info{
		Name:        "base32",
		Description: "Standard Base32 with padding (RFC 4648 §6)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "Base32 text (uppercase)",
		Parameters:  []string{"decode is case-insensitive", "decode ignores ASCII whitespace"},
	}
}

func (base32Codec) Encode(data []byte) ([]byte, error) {
	out := make([]byte, base32Encoding.EncodedLen(len(data)))
	base32Encoding.Encode(out, data)
	return out, nil
}

func (base32Codec) Decode(data []byte) ([]byte, error) {
	clean := stripWhitespace(data)
	out, err := base32Encoding.DecodeString(strings.ToUpper(string(clean)))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid base32 input")
	}
	return out, nil
}

// ---------------------------------------------------------------- ascii85

type ascii85Codec struct{}

func (ascii85Codec) Info() registry.Info {
	return registry.Info{
		Name:        "ascii85",
		Description: "Adobe/ASCII85 text (Go standard library encoding/ascii85)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "ASCII85 text",
		Parameters:  []string{"decode ignores ASCII whitespace"},
	}
}

func (ascii85Codec) Encode(data []byte) ([]byte, error) {
	out := make([]byte, ascii85.MaxEncodedLen(len(data)))
	n := ascii85.Encode(out, data)
	return out[:n], nil
}

func (ascii85Codec) Decode(data []byte) ([]byte, error) {
	clean := stripWhitespace(data)
	// Go's decoder writes whole 4-byte groups internally, so leave headroom
	// for a partial final block even when len(clean) < 4.
	out := make([]byte, len(clean)+4)
	n, _, err := ascii85.Decode(out, clean, true)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid ascii85 input")
	}
	return out[:n], nil
}

// ---------------------------------------------------------------- raw

type rawCodec struct{}

func (rawCodec) Info() registry.Info {
	return registry.Info{
		Name:        "raw",
		Description: "Identity: preserve exact bytes without representation change",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "bytes",
	}
}

func (rawCodec) Encode(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (rawCodec) Decode(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func stripWhitespace(data []byte) []byte {
	return bytes.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			return -1
		default:
			return r
		}
	}, data)
}
