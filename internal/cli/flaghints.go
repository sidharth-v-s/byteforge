package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/codec"
	"github.com/zoro/byteforge/internal/cryptography"
	"github.com/zoro/byteforge/internal/renderer"
	"github.com/zoro/byteforge/internal/transform"
)

// flagParseError turns the standard library's terse flag errors into actionable
// messages. In particular, a flag with no value should say what values it
// accepts instead of only repeating the flag name.
func flagParseError(fs *flag.FlagSet, err error) error {
	if name, ok := missingFlagValue(err); ok {
		return bferrors.New(bferrors.Usage,
			"missing value for %s; %s (run '%s --help' for usage)",
			displayFlagName(name), flagValueHint(fs, name), fs.Name())
	}
	if name, value, ok := invalidFlagValue(err); ok {
		return bferrors.New(bferrors.Usage,
			"invalid value %q for %s; %s (run '%s --help' for usage)",
			value, displayFlagName(name), flagValueHint(fs, name), fs.Name())
	}
	return bferrors.New(bferrors.Usage, "%s (run '%s --help' for usage)", err, fs.Name())
}

func displayFlagName(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

func missingFlagValue(err error) (string, bool) {
	const prefix = "flag needs an argument: "
	msg := err.Error()
	if !strings.HasPrefix(msg, prefix) {
		return "", false
	}
	name := strings.TrimLeft(strings.TrimSpace(strings.TrimPrefix(msg, prefix)), "-")
	return name, name != ""
}

func invalidFlagValue(err error) (name, value string, ok bool) {
	const prefix = "invalid value "
	const separator = `" for flag -`
	msg := err.Error()
	if !strings.HasPrefix(msg, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(msg, prefix)
	i := strings.Index(rest, separator)
	if i < 0 {
		return "", "", false
	}
	value = strings.Trim(rest[:i], `"`)
	name = rest[i+len(separator):]
	if j := strings.IndexByte(name, ':'); j >= 0 {
		name = name[:j]
	}
	name = strings.TrimSpace(name)
	return name, value, name != ""
}

// flagValueHint lists the accepted values for flagged enums and describes the
// expected form for every other non-boolean flag.
func flagValueHint(fs *flag.FlagSet, name string) string {
	switch name {
	case "renderer":
		return "available renderers: " + strings.Join(renderer.Names(), ", ")
	case "encoding":
		return "available codecs: " + strings.Join(codec.Names(), ", ")
	case "cipher":
		return "available ciphers: " + strings.Join(cryptography.Names(), ", ")
	case "transform":
		return "available transforms: " + strings.Join(transform.Names(), ", ")
	case "file", "f", "output", "o", "key-file", "password-file", "export-key", "original", "recovered":
		return "expected a file path"
	case "hex", "s":
		return "expected a hexadecimal string"
	case "key":
		return "expected hexadecimal key material"
	case "password":
		return "expected a password string"
	case "nonce":
		return "expected hexadecimal nonce/IV bytes"
	case "aad":
		return "expected UTF-8 text"
	case "sha256":
		return "expected a 64-character hexadecimal SHA-256 digest"
	case "symbol":
		return "expected an identifier matching [A-Za-z_][A-Za-z0-9_]*"
	case "key-symbol":
		return "expected an identifier matching [A-Za-z_][A-Za-z0-9_]* (leading $ optional for PowerShell)"
	case "bytes-per-line":
		return "expected an integer from 1 to 256"
	case "pad":
		return "use none, nop (0x90), zero (0x00), random (crypto/rand), or hex bytes such as CC or 9090"
	case "pad-to":
		return "expected an integer byte multiple from 1 to 1048576"
	case "max-input":
		return "expected a positive byte count"
	}
	if f := fs.Lookup(name); f != nil && f.Usage != "" {
		return fmt.Sprintf("expected a value for %s", f.Usage)
	}
	return "expected a value"
}
