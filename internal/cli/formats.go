package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/codec"
	"github.com/zoro/byteforge/internal/cryptography"
	"github.com/zoro/byteforge/internal/registry"
	"github.com/zoro/byteforge/internal/renderer"
	"github.com/zoro/byteforge/internal/transform"
	"github.com/zoro/byteforge/internal/version"
)

type formatsDocument struct {
	Tool                 string          `json:"tool"`
	Version              string          `json:"version"`
	Codecs               []registry.Info `json:"codecs"`
	Transforms           []registry.Info `json:"transforms"`
	ModernCiphers        []registry.Info `json:"modernCiphers"`
	CompatibilityCiphers []registry.Info `json:"compatibilityCiphers"`
	LegacyCiphers        []registry.Info `json:"legacyCiphers"`
	Renderers            []registry.Info `json:"renderers"`
}

func (a *App) cmdFormats(args []string) error {
	fs := a.newFlagSet("formats", formatsUsage)
	jsonOut := false
	fs.BoolVar(&jsonOut, "json", false, "emit JSON")
	a.registerCommon(fs)
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}

	codecs := codecInfos()
	transforms := transformInfos()
	modern, compat, legacy := cipherInfosByClass()
	renderers := rendererInfos()

	var out []byte
	if jsonOut {
		doc := formatsDocument{
			Tool:                 "byteforge",
			Version:              version.Version,
			Codecs:               codecs,
			Transforms:           transforms,
			ModernCiphers:        modern,
			CompatibilityCiphers: compat,
			LegacyCiphers:        legacy,
			Renderers:            renderers,
		}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return bferrors.Wrap(bferrors.Processing, err, "encoding formats JSON")
		}
		out = append(data, '\n')
	} else {
		out = []byte(formatFormats(codecs, transforms, modern, compat, legacy, renderers, a.rep.Verbose()))
	}

	path, err := a.writeOutput(out)
	if err != nil {
		return err
	}
	if path != "stdout" {
		a.rep.OK("format listing written to %s", path)
	}
	return nil
}

func codecInfos() []registry.Info {
	all := codec.All()
	out := make([]registry.Info, len(all))
	for i, c := range all {
		out[i] = c.Info()
	}
	return out
}

func transformInfos() []registry.Info {
	all := transform.All()
	out := make([]registry.Info, len(all))
	for i, t := range all {
		out[i] = t.Info()
	}
	return out
}

func cipherInfosByClass() (modern, compat, legacy []registry.Info) {
	for _, c := range cryptography.All() {
		info := c.Info()
		switch info.Security {
		case registry.SecurityAuthenticated:
			modern = append(modern, info)
		case registry.SecurityCompatibility:
			compat = append(compat, info)
		case registry.SecurityLegacy:
			legacy = append(legacy, info)
		}
	}
	return modern, compat, legacy
}

func rendererInfos() []registry.Info {
	all := renderer.All()
	out := make([]registry.Info, len(all))
	for i, r := range all {
		out[i] = r.Info()
		if renderer.KeyCapable(out[i].Name) {
			out[i].Parameters = append(out[i].Parameters, "--key-symbol NAME (encrypt; key always included)")
		}
	}
	return out
}

func formatFormats(codecs, transforms, modern, compat, legacy, renderers []registry.Info, verbose bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ByteForge %s — supported formats\n", version.Version)
	fmt.Fprintf(&b, "Default cipher: aes-256-gcm (authenticated). Encryption is not encoding.\n")

	writeGroup(&b, "Representation codecs (reversible; not encryption)", "", codecs, verbose)
	writeGroup(&b, "Reversible transforms (educational obfuscation; not secure encryption)",
		"Grouped separately because XOR is not encryption.", transforms, verbose)
	writeGroup(&b, "Cryptographic algorithms (authenticated encryption; recommended)",
		"Every entry is authenticated and rejects tampered data.", modern, verbose)
	writeGroup(&b, "Compatibility ciphers (authenticated with HMAC-SHA256; prefer AES-GCM)",
		"Non-AEAD modes are wrapped with encrypt-then-MAC and verify before decrypting.", compat, verbose)
	writeGroup(&b, "Legacy algorithms (disabled by default; require --allow-legacy)",
		"Exposed only for legacy interoperability or demonstrations.", legacy, verbose)
	writeGroup(&b, "Output renderers (format transformed bytes)", "", renderers, verbose)

	fmt.Fprintf(&b, "\nPayload padding (optional; explicit, never implicit)\n")
	fmt.Fprintf(&b, "  Encode only pads fixed-width codecs: ipv4, ipv6, mac, uuid and\n")
	fmt.Fprintf(&b, "  their -list variants. Other encodings ignore --pad with a warning.\n")
	fmt.Fprintf(&b, "  --pad MODE         none (reject misalignment), nop (0x90), zero (0x00),\n")
	fmt.Fprintf(&b, "                     random (crypto/rand; default when padding is enabled),\n")
	fmt.Fprintf(&b, "                     or hex bytes such as CC or 9090\n")
	fmt.Fprintf(&b, "  --pad-to N         multiple in bytes; must match the codec width\n")
	fmt.Fprintf(&b, "  --pad              bare form selects random padding\n")

	fmt.Fprintf(&b, "\nExamples:\n")
	fmt.Fprintf(&b, "  byteforge encode --file input.bin --encoding base64 --output payload.txt\n")
	fmt.Fprintf(&b, "  byteforge encrypt --file input.bin --password-stdin --output sample.bf\n")
	fmt.Fprintf(&b, "  byteforge decrypt --file sample.bf --password-stdin --output recovered.bin\n")
	return b.String()
}

func writeGroup(b *strings.Builder, title, note string, infos []registry.Info, verbose bool) {
	fmt.Fprintf(b, "\n%s\n", title)
	if note != "" {
		fmt.Fprintf(b, "  %s\n", note)
	}
	for _, info := range infos {
		fmt.Fprintf(b, "  %-18s %s\n", info.Name, info.Description)
		var extras []string
		if info.Output != "" && info.Output != "bytes" && verbose {
			extras = append(extras, "output: "+info.Output)
		}
		if len(info.Parameters) > 0 {
			extras = append(extras, strings.Join(info.Parameters, "; "))
		}
		if len(extras) > 0 {
			fmt.Fprintf(b, "  %-18s   %s\n", "", strings.Join(extras, " | "))
		}
		if info.Warning != "" {
			fmt.Fprintf(b, "  %-18s   WARNING: %s\n", "", info.Warning)
		}
	}
}
