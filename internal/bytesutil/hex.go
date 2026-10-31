// Package bytesutil contains small binary parsing helpers shared by the
// input loader and the hexadecimal codec.
package bytesutil

import (
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
)

// ParseHex parses a loose hexadecimal string into bytes.
//
// Accepted whitespace and separators: spaces, tabs, newlines, carriage
// returns, ':', '-', ',' and '_'. Optional "0x"/"0X" and "\x"/"\X" prefixes
// are stripped per byte group. Everything else must be a hex digit, and the
// remaining digit count must be even.
//
// The laxness is intentional for copy/paste interoperability; odd length and
// non-hex characters are always rejected.
func ParseHex(s string) ([]byte, error) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
			c == ':' || c == '-' || c == ',' || c == '_':
			i++
		case (c == '0' || c == '\\') && i+1 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X'):
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}

	h := b.String()
	if h == "" {
		return nil, bferrors.New(bferrors.Usage, "hex input is empty")
	}
	if len(h)%2 != 0 {
		return nil, bferrors.New(bferrors.Usage, "hex input has odd length (%d digits): incomplete byte", len(h))
	}
	for i := 0; i < len(h); i++ {
		if !isHex(h[i]) {
			return nil, bferrors.New(bferrors.Usage, "hex input contains invalid character %q", h[i])
		}
	}

	out := make([]byte, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		out[i/2] = unhex(h[i])<<4 | unhex(h[i+1])
	}
	return out, nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
