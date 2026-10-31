package renderer

import (
	"encoding/base64"
	"sort"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/registry"
)

// keySourceRenderers can carry payload and key material in one source file as
// two separate data declarations. Renderers that produce bare bytes or a
// single text value are intentionally excluded: concatenating a second value
// would make the output ambiguous.
var keySourceRenderers = map[string]bool{
	"c-array":          true,
	"csharp-array":     true,
	"go-bytes":         true,
	"javascript-array": true,
	"nim-array":        true,
	"powershell-bytes": true,
	"python-bytes":     true,
	"rust-array":       true,
	"vba-array":        true,
	"vbs-array":        true,
	"zig-array":        true,
}

// KeyCapable reports whether name can emit payload and key material together.
func KeyCapable(name string) bool {
	return name == "json" || keySourceRenderers[name]
}

// KeyCapableNames returns key-capable renderer identifiers sorted by name.
func KeyCapableNames() []string {
	names := make([]string, 0, len(keySourceRenderers)+1)
	for name := range keySourceRenderers {
		names = append(names, name)
	}
	names = append(names, "json")
	sort.Strings(names)
	return names
}

// RenderWithKey renders data and key material using the same renderer.
//
// Source renderers emit a second declaration with keySymbol. The key header
// deliberately omits the operation and digest so the output does not expose a
// hash of the secret. JSON embeds a key object with Base64 data. The caller is
// responsible for warning that the result contains a secret.
func RenderWithKey(name string, data, key []byte, meta registry.Meta, keySymbol string) ([]byte, error) {
	if keySymbol == "" {
		keySymbol = "key"
	}
	if name == "json" {
		return jsonRenderer{}.render(data, meta, &jsonKeyDocument{
			Symbol:   keySymbol,
			Encoding: "base64",
			Size:     len(key),
			Data:     base64.StdEncoding.EncodeToString(key),
		})
	}
	if !keySourceRenderers[name] {
		return nil, bferrors.New(bferrors.Usage,
			"renderer %s cannot include key material in the same output; use a key-capable renderer (%s) or --export-key FILE",
			name, strings.Join(KeyCapableNames(), ", "))
	}
	if effectiveSymbol(name, keySymbol) == effectiveSymbol(name, meta.Symbol) {
		return nil, bferrors.New(bferrors.Usage,
			"key symbol %q conflicts with the data symbol; choose a different --key-symbol", keySymbol)
	}
	r, ok := Get(name)
	if !ok {
		return nil, bferrors.New(bferrors.Usage, "unknown renderer %q", name)
	}

	dataOut, err := r.Render(data, meta)
	if err != nil {
		return nil, err
	}

	keyMeta := meta
	keyMeta.Operation = ""
	keyMeta.Format = ""
	keyMeta.Encoding = ""
	keyMeta.Cipher = ""
	keyMeta.InputSize = 0
	keyMeta.InputSHA256 = ""
	keyMeta.Verification = ""
	keyMeta.Symbol = keySymbol
	keyOut, err := r.Render(key, keyMeta)
	if err != nil {
		return nil, err
	}

	var b strings.Builder
	b.Grow(len(dataOut) + len(keyOut) + 2)
	b.Write(dataOut)
	if len(dataOut) == 0 || dataOut[len(dataOut)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(keyOut)
	return []byte(b.String()), nil
}

func effectiveSymbol(name, symbol string) string {
	if name == "powershell-bytes" {
		symbol = strings.TrimPrefix(symbol, "$")
	}
	if symbol == "" || (name == "python-bytes" && symbol == "_") {
		return "data"
	}
	return symbol
}
