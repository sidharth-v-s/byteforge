package codec

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/bytesutil"
	"github.com/zoro/byteforge/internal/registry"
)

func init() {
	Register(macCodec{})
	Register(ipv4Codec{})
	Register(ipv6Codec{})
	Register(uuidCodec{})
	Register(decimalCodec{})
	Register(octalCodec{})
	Register(binaryCodec{})
	Register(cEscapedCodec{})
	Register(unicodeEscapeCodec{})
}

func requireLen(name string, data []byte, want int) error {
	if len(data) != want {
		hint := ""
		if len(data) > want {
			if list := listCodecFor(name); list != "" {
				hint = fmt.Sprintf("; use --encoding %s for a sequence", list)
			}
		}
		return bferrors.New(bferrors.Usage,
			"%s requires exactly %d bytes, got %d%s", name, want, len(data), hint)
	}
	return nil
}

// ---------------------------------------------------------------- mac

type macCodec struct{}

func (macCodec) Info() registry.Info {
	return registry.Info{
		Name:        "mac",
		Description: "EUI-48/MAC address text (AA:BB:CC:DD:EE:FF)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "exactly 6 bytes",
		Output:      "colon-separated MAC text",
		Parameters:  []string{"decode accepts ':', '-', '.' and whitespace separators", "exactly 6 octets"},
	}
}

func (macCodec) ExactWidth() int { return 6 }

func (macCodec) Encode(data []byte) ([]byte, error) {
	if err := requireLen("mac", data, 6); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		data[0], data[1], data[2], data[3], data[4], data[5])), nil
}

func (macCodec) Decode(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	replacer := strings.NewReplacer(":", "", "-", "", ".", "", " ", "", "\t", "")
	out, err := bytesutil.ParseHex(replacer.Replace(s))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid MAC address")
	}
	if err := requireLen("mac", out, 6); err != nil {
		return nil, bferrors.New(bferrors.Processing, "invalid MAC address: expected 6 octets, got %d", len(out))
	}
	return out, nil
}

// ---------------------------------------------------------------- ipv4

type ipv4Codec struct{}

func (ipv4Codec) Info() registry.Info {
	return registry.Info{
		Name:        "ipv4",
		Description: "Dotted-quad IPv4 address text",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "exactly 4 bytes",
		Output:      "IPv4 dotted-quad text",
		Parameters:  []string{"exactly 4 bytes", "IPv6 text is rejected"},
	}
}

func (ipv4Codec) ExactWidth() int { return 4 }

func (ipv4Codec) Encode(data []byte) ([]byte, error) {
	if err := requireLen("ipv4", data, 4); err != nil {
		return nil, err
	}
	return []byte(net.IPv4(data[0], data[1], data[2], data[3]).String()), nil
}

func (ipv4Codec) Decode(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	if strings.Contains(s, ":") {
		return nil, bferrors.New(bferrors.Processing, "invalid IPv4 address %q: IPv6 form is not accepted", s)
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil, bferrors.New(bferrors.Processing, "invalid IPv4 address %q", s)
	}
	return ip.To4(), nil
}

// ---------------------------------------------------------------- ipv6

type ipv6Codec struct{}

func (ipv6Codec) Info() registry.Info {
	return registry.Info{
		Name:        "ipv6",
		Description: "Canonical IPv6 address text",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "exactly 16 bytes",
		Output:      "canonical IPv6 text",
		Parameters:  []string{"exactly 16 bytes", "IPv4 text is rejected"},
	}
}

func (ipv6Codec) ExactWidth() int { return 16 }

func (ipv6Codec) Encode(data []byte) ([]byte, error) {
	if err := requireLen("ipv6", data, 16); err != nil {
		return nil, err
	}
	return []byte(net.IP(data).String()), nil
}

func (ipv6Codec) Decode(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return nil, bferrors.New(bferrors.Processing, "invalid IPv6 address %q", s)
	}
	if len(ip) != 16 {
		return nil, bferrors.New(bferrors.Processing, "invalid IPv6 address %q", s)
	}
	return ip, nil
}

// ---------------------------------------------------------------- uuid

type uuidCodec struct{}

func (uuidCodec) Info() registry.Info {
	return registry.Info{
		Name:        "uuid",
		Description: "RFC 4122 canonical UUID text (network byte order)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "exactly 16 bytes",
		Output:      "canonical UUID text",
		Parameters:  []string{"exactly 16 bytes", "canonical hyphenated form only", "does not imply a generated/valid UUID"},
	}
}

func (uuidCodec) ExactWidth() int { return 16 }

func (uuidCodec) Encode(data []byte) ([]byte, error) {
	if err := requireLen("uuid", data, 16); err != nil {
		return nil, err
	}
	h := fmt.Sprintf("%x", data)
	return []byte(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]), nil
}

func (uuidCodec) Decode(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, bferrors.New(bferrors.Processing, "invalid UUID %q: expected canonical xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form", s)
	}
	compact := strings.ReplaceAll(s, "-", "")
	out, err := bytesutil.ParseHex(compact)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Processing, err, "invalid UUID %q", s)
	}
	if len(out) != 16 {
		return nil, bferrors.New(bferrors.Processing, "invalid UUID %q", s)
	}
	return out, nil
}

// ---------------------------------------------------------------- decimal / octal / binary

func splitByteTokens(data []byte) []string {
	return strings.FieldsFunc(strings.TrimSpace(string(data)), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ',' || r == ';'
	})
}

type decimalCodec struct{}

func (decimalCodec) Info() registry.Info {
	return registry.Info{
		Name:        "decimal",
		Description: "Space-separated decimal byte list (0-255)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "decimal byte list text",
		Parameters:  []string{"unsigned values 0-255", "separators: whitespace, comma, semicolon"},
	}
}

func (decimalCodec) Encode(data []byte) ([]byte, error) {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = strconv.Itoa(int(b))
	}
	return []byte(strings.Join(parts, " ")), nil
}

func (decimalCodec) Decode(data []byte) ([]byte, error) {
	tokens := splitByteTokens(data)
	out := make([]byte, 0, len(tokens))
	for _, tok := range tokens {
		v, err := strconv.ParseUint(tok, 10, 8)
		if err != nil {
			return nil, bferrors.New(bferrors.Processing, "invalid decimal byte %q: expected 0-255", tok)
		}
		out = append(out, byte(v))
	}
	return out, nil
}

type octalCodec struct{}

func (octalCodec) Info() registry.Info {
	return registry.Info{
		Name:        "octal",
		Description: "Space-separated three-digit octal byte list",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "octal byte list text",
		Parameters:  []string{"encode emits 000-377", "decode accepts optional 0o or backslash prefix"},
	}
}

func (octalCodec) Encode(data []byte) ([]byte, error) {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%03o", b)
	}
	return []byte(strings.Join(parts, " ")), nil
}

func (octalCodec) Decode(data []byte) ([]byte, error) {
	tokens := splitByteTokens(data)
	out := make([]byte, 0, len(tokens))
	for _, tok := range tokens {
		t := tok
		if strings.HasPrefix(t, "0o") || strings.HasPrefix(t, "0O") {
			t = t[2:]
		} else if strings.HasPrefix(t, "\\") {
			t = t[1:]
		}
		if t == "" || len(t) > 3 {
			return nil, bferrors.New(bferrors.Processing, "invalid octal byte %q: expected 1-3 octal digits", tok)
		}
		v, err := strconv.ParseUint(t, 8, 8)
		if err != nil {
			return nil, bferrors.New(bferrors.Processing, "invalid octal byte %q: expected 0-377", tok)
		}
		out = append(out, byte(v))
	}
	return out, nil
}

type binaryCodec struct{}

func (binaryCodec) Info() registry.Info {
	return registry.Info{
		Name:        "binary",
		Description: "Space-separated eight-bit groups",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "binary byte list text",
		Parameters:  []string{"each group must be exactly 8 bits", "optional 0b prefix per group"},
	}
}

func (binaryCodec) Encode(data []byte) ([]byte, error) {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("%08b", b)
	}
	return []byte(strings.Join(parts, " ")), nil
}

func (binaryCodec) Decode(data []byte) ([]byte, error) {
	tokens := splitByteTokens(data)
	// Accept a single long run of bits as a convenience.
	if len(tokens) == 1 && len(tokens[0]) > 8 && len(tokens[0])%8 == 0 {
		run := tokens[0]
		tokens = make([]string, 0, len(run)/8)
		for i := 0; i < len(run); i += 8 {
			tokens = append(tokens, run[i:i+8])
		}
	}
	out := make([]byte, 0, len(tokens))
	for _, tok := range tokens {
		t := strings.TrimPrefix(strings.TrimPrefix(tok, "0b"), "0B")
		if len(t) != 8 {
			return nil, bferrors.New(bferrors.Processing, "invalid binary byte %q: expected exactly 8 bits", tok)
		}
		v, err := strconv.ParseUint(t, 2, 8)
		if err != nil {
			return nil, bferrors.New(bferrors.Processing, "invalid binary byte %q: expected only 0 and 1", tok)
		}
		out = append(out, byte(v))
	}
	return out, nil
}

// ---------------------------------------------------------------- c-escaped

type cEscapedCodec struct{}

func (cEscapedCodec) Info() registry.Info {
	return registry.Info{
		Name:        "c-escaped",
		Description: "C-style escaped byte string as data (not executable code)",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "quoted C string literal text",
		Parameters:  []string{"decode supports \\xHH, octal escapes, and common single-character escapes", "no implicit NUL terminator"},
	}
}

func (cEscapedCodec) Encode(data []byte) ([]byte, error) {
	var b strings.Builder
	b.Grow(len(data)*4 + 2)
	b.WriteByte('"')
	for _, by := range data {
		fmt.Fprintf(&b, "\\x%02x", by)
	}
	b.WriteByte('"')
	return []byte(b.String()), nil
}

func (cEscapedCodec) Decode(data []byte) ([]byte, error) {
	s := strings.TrimSpace(string(data))
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return nil, bferrors.New(bferrors.Processing, "invalid c-escaped string: expected surrounding double quotes")
	}
	s = s[1 : len(s)-1]

	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, bferrors.New(bferrors.Processing, "invalid c-escaped string: trailing backslash")
		}
		e := s[i+1]
		switch e {
		case 'x':
			if i+3 >= len(s) || !isHexByte(s[i+2]) || !isHexByte(s[i+3]) {
				return nil, bferrors.New(bferrors.Processing, "invalid c-escaped string: \\x requires two hex digits")
			}
			out = append(out, hexPair(s[i+2], s[i+3]))
			i += 4
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j := i + 1
			val := 0
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
			}
			if val > 255 {
				return nil, bferrors.New(bferrors.Processing, "invalid c-escaped string: octal escape exceeds one byte")
			}
			out = append(out, byte(val))
			i = j
		case 'n':
			out = append(out, '\n')
			i += 2
		case 'r':
			out = append(out, '\r')
			i += 2
		case 't':
			out = append(out, '\t')
			i += 2
		case 'a':
			out = append(out, 0x07)
			i += 2
		case 'b':
			out = append(out, 0x08)
			i += 2
		case 'f':
			out = append(out, 0x0c)
			i += 2
		case 'v':
			out = append(out, 0x0b)
			i += 2
		case '\\':
			out = append(out, '\\')
			i += 2
		case '"':
			out = append(out, '"')
			i += 2
		case '\'':
			out = append(out, '\'')
			i += 2
		default:
			return nil, bferrors.New(bferrors.Processing, "invalid c-escaped string: unsupported escape \\%c", e)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- unicode-escape

type unicodeEscapeCodec struct{}

func (unicodeEscapeCodec) Info() registry.Info {
	return registry.Info{
		Name:        "unicode-escape",
		Description: "Latin-1 byte-to-code-point escapes (\\u00HH), unambiguous for 0x00-0xFF",
		Security:    registry.SecurityRepresentation,
		Reversible:  true,
		Input:       "any bytes",
		Output:      "\\u00HH text",
		Parameters:  []string{"each byte maps to U+00HH", "decode accepts whitespace between escapes"},
	}
}

func (unicodeEscapeCodec) Encode(data []byte) ([]byte, error) {
	var b strings.Builder
	b.Grow(len(data) * 6)
	for _, by := range data {
		fmt.Fprintf(&b, "\\u%04x", by)
	}
	return []byte(b.String()), nil
}

func (unicodeEscapeCodec) Decode(data []byte) ([]byte, error) {
	s := string(data)
	out := make([]byte, 0, len(s)/6)
	for i := 0; i < len(s); {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			i++
			continue
		}
		if i+6 > len(s) || s[i] != '\\' || s[i+1] != 'u' ||
			s[i+2] != '0' || s[i+3] != '0' ||
			!isHexByte(s[i+4]) || !isHexByte(s[i+5]) {
			return nil, bferrors.New(bferrors.Processing, "invalid unicode-escape input at offset %d: expected \\u00HH", i)
		}
		out = append(out, hexPair(s[i+4], s[i+5]))
		i += 6
	}
	return out, nil
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexPair(a, b byte) byte {
	return hexVal(a)<<4 | hexVal(b)
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
