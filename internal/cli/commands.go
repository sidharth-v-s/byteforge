package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/bytesutil"
	"github.com/zoro/byteforge/internal/codec"
	"github.com/zoro/byteforge/internal/cryptography"
	"github.com/zoro/byteforge/internal/input"
	"github.com/zoro/byteforge/internal/inspect"
	"github.com/zoro/byteforge/internal/padding"
	"github.com/zoro/byteforge/internal/pipeline"
	"github.com/zoro/byteforge/internal/renderer"
	"github.com/zoro/byteforge/internal/reporting"
	"github.com/zoro/byteforge/internal/transform"
	"github.com/zoro/byteforge/internal/version"
)

// ---------------------------------------------------------------- encode

func (a *App) cmdEncode(args []string) error {
	var f struct {
		input    inputFlags
		render   renderFlags
		encoding string
		noVerify bool
	}
	fs := a.newFlagSet("encode", encodeUsage)
	a.registerCommon(fs)
	a.registerInputFlags(fs, &f.input)
	fs.StringVar(&f.encoding, "encoding", "", "codec identifier (required)")
	a.registerRenderFlags(fs, &f.render)
	fs.BoolVar(&f.noVerify, "no-verify", false, "skip round-trip verification")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	a.rep.Banner()

	if f.encoding == "" {
		return bferrors.New(bferrors.Usage, "encode requires --encoding (run 'byteforge formats' to list codecs)")
	}
	c, ok := codec.Get(f.encoding)
	if !ok {
		return unknownName("codec", f.encoding, codec.Names())
	}
	if err := validateRender(&f.render); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}
	src, err := a.loadInput(&f.input)
	if err != nil {
		return err
	}
	a.rep.Info("loaded %d bytes from %s", len(src.Data), src.Label)

	workData, padResult, err := a.encodePadding(src.Data, &f.render, c.Info().Name)
	if err != nil {
		return err
	}

	encoded, timings, err := pipeline.Run(workData, []pipeline.Stage{
		{Name: "encode/" + c.Info().Name, Fn: c.Encode},
	})
	if err != nil {
		return err
	}

	verification := "SKIPPED"
	if !f.noVerify {
		decoded, vErr := c.Decode(encoded)
		if vErr != nil {
			return bferrors.Wrap(bferrors.Verification, vErr, "round-trip verification failed for %s", c.Info().Name)
		}
		if !bytes.Equal(decoded, workData) {
			return bferrors.New(bferrors.Verification,
				"round-trip verification failed for %s: decoded bytes differ from input", c.Info().Name)
		}
		verification = "PASSED"
	}

	rend, _ := renderer.Get(f.render.name)
	out, err := rend.Render(encoded, a.meta("encode", c.Info().Name, c.Info().Name, "", verification, src.Data, &f.render))
	if err != nil {
		return err
	}
	path, err := a.emit(out, f.render.name)
	if err != nil {
		return err
	}

	a.verboseDetails("Input", src.Data, timings)
	a.verboseDetails("Output", out, nil)
	fields := []reporting.Field{
		{Key: "Operation", Value: "encode"},
		{Key: "Encoding", Value: c.Info().Name},
		{Key: "Renderer", Value: f.render.name},
		{Key: "Input size", Value: fmt.Sprintf("%d bytes", len(src.Data))},
		{Key: "Output size", Value: fmt.Sprintf("%d bytes", len(out))},
		{Key: "Size delta", Value: delta(len(src.Data), len(out))},
		{Key: "Input SHA-256", Value: sha256Hex(src.Data)},
		{Key: "Output SHA-256", Value: sha256Hex(out)},
		{Key: "Verification", Value: verification},
		{Key: "Output file", Value: path},
	}
	fields = append(fields, paddingFields(padResult)...)
	a.summary(fields)
	return nil
}

// ---------------------------------------------------------------- decode

func (a *App) cmdDecode(args []string) error {
	var f struct {
		input    inputFlags
		render   renderFlags
		encoding string
		noVerify bool
	}
	fs := a.newFlagSet("decode", decodeUsage)
	a.registerCommon(fs)
	a.registerInputFlags(fs, &f.input)
	fs.StringVar(&f.encoding, "encoding", "", "codec identifier (required)")
	a.registerRenderFlags(fs, &f.render)
	fs.BoolVar(&f.noVerify, "no-verify", false, "skip round-trip verification")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	a.rep.Banner()

	if f.encoding == "" {
		return bferrors.New(bferrors.Usage, "decode requires --encoding (run 'byteforge formats' to list codecs)")
	}
	c, ok := codec.Get(f.encoding)
	if !ok {
		return unknownName("codec", f.encoding, codec.Names())
	}
	if err := validateRender(&f.render); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}
	src, err := a.loadInput(&f.input)
	if err != nil {
		return err
	}
	a.rep.Info("loaded %d bytes from %s", len(src.Data), src.Label)

	decoded, timings, err := pipeline.Run(src.Data, []pipeline.Stage{
		{Name: "decode/" + c.Info().Name, Fn: c.Decode},
	})
	if err != nil {
		return err
	}

	decoded, padResult, err := a.applyPadding(decoded, &f.render, f.encoding)
	if err != nil {
		return err
	}

	verification := "SKIPPED"
	if !f.noVerify {
		reenc, vErr := c.Encode(decoded)
		if vErr != nil {
			return bferrors.Wrap(bferrors.Verification, vErr, "round-trip verification failed for %s", c.Info().Name)
		}
		redec, vErr := c.Decode(reenc)
		if vErr != nil {
			return bferrors.Wrap(bferrors.Verification, vErr, "round-trip verification failed for %s", c.Info().Name)
		}
		if !bytes.Equal(redec, decoded) {
			return bferrors.New(bferrors.Verification,
				"round-trip verification failed for %s: re-decoded bytes differ", c.Info().Name)
		}
		verification = "PASSED"
	}

	rend, _ := renderer.Get(f.render.name)
	out, err := rend.Render(decoded, a.meta("decode", c.Info().Name, c.Info().Name, "", verification, src.Data, &f.render))
	if err != nil {
		return err
	}
	path, err := a.emit(out, f.render.name)
	if err != nil {
		return err
	}

	a.verboseDetails("Input", src.Data, timings)
	a.verboseDetails("Output", out, nil)
	fields := []reporting.Field{
		{Key: "Operation", Value: "decode"},
		{Key: "Encoding", Value: c.Info().Name},
		{Key: "Renderer", Value: f.render.name},
		{Key: "Input size", Value: fmt.Sprintf("%d bytes", len(src.Data))},
		{Key: "Output size", Value: fmt.Sprintf("%d bytes", len(out))},
		{Key: "Size delta", Value: delta(len(src.Data), len(out))},
		{Key: "Input SHA-256", Value: sha256Hex(src.Data)},
		{Key: "Output SHA-256", Value: sha256Hex(out)},
		{Key: "Verification", Value: verification},
		{Key: "Output file", Value: path},
	}
	fields = append(fields, paddingFields(padResult)...)
	a.summary(fields)
	return nil
}

// ---------------------------------------------------------------- transform

func (a *App) cmdTransform(args []string, op string) error {
	var f struct {
		input    inputFlags
		render   renderFlags
		name     string
		keyHex   string
		keyFile  string
		noVerify bool
	}
	fs := a.newFlagSet(op, transformUsage)
	a.registerCommon(fs)
	a.registerInputFlags(fs, &f.input)
	fs.StringVar(&f.name, "transform", "", "transform identifier (required)")
	fs.StringVar(&f.keyHex, "key", "", "transform key as hex (required)")
	fs.StringVar(&f.keyFile, "key-file", "", "read transform key as hex from FILE")
	a.registerRenderFlags(fs, &f.render)
	fs.BoolVar(&f.noVerify, "no-verify", false, "skip double-application verification")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	a.rep.Banner()

	if f.name == "" {
		return bferrors.New(bferrors.Usage, "%s requires --transform (available: %s)", op, strings.Join(transform.Names(), ", "))
	}
	t, ok := transform.Get(f.name)
	if !ok {
		return unknownName("transform", f.name, transform.Names())
	}
	if err := validateRender(&f.render); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}
	key, err := readTransformKey(f.keyHex, f.keyFile)
	if err != nil {
		return err
	}
	if err := t.ValidateKey(key); err != nil {
		return err
	}
	src, err := a.loadInput(&f.input)
	if err != nil {
		return err
	}
	a.rep.Info("loaded %d bytes from %s", len(src.Data), src.Label)

	workData := src.Data
	var padResult *padding.Result
	if op == "transform" {
		workData, padResult, err = a.applyPadding(src.Data, &f.render, "")
		if err != nil {
			return err
		}
	}

	outData, timings, err := pipeline.Run(workData, []pipeline.Stage{
		{Name: op + "/" + t.Info().Name, Fn: func(data []byte) ([]byte, error) { return t.Apply(data, key) }},
	})
	if err != nil {
		return err
	}

	verification := "SKIPPED"
	if !f.noVerify {
		restored, vErr := t.Apply(outData, key)
		if vErr != nil {
			return bferrors.Wrap(bferrors.Verification, vErr, "round-trip verification failed")
		}
		if !bytes.Equal(restored, workData) {
			return bferrors.New(bferrors.Verification, "round-trip verification failed: restored bytes differ")
		}
		verification = "PASSED"
	}

	if op == "untransform" {
		outData, padResult, err = a.applyPadding(outData, &f.render, "")
		if err != nil {
			return err
		}
	}

	rend, _ := renderer.Get(f.render.name)
	out, err := rend.Render(outData, a.meta(op, t.Info().Name, "", "", verification, src.Data, &f.render))
	if err != nil {
		return err
	}
	path, err := a.emit(out, f.render.name)
	if err != nil {
		return err
	}

	a.verboseDetails("Input", src.Data, timings)
	a.verboseDetails("Output", out, nil)
	fields := []reporting.Field{
		{Key: "Operation", Value: op},
		{Key: "Transform", Value: t.Info().Name},
		{Key: "Key size", Value: fmt.Sprintf("%d bytes (not displayed)", len(key))},
		{Key: "Renderer", Value: f.render.name},
		{Key: "Input size", Value: fmt.Sprintf("%d bytes", len(src.Data))},
		{Key: "Output size", Value: fmt.Sprintf("%d bytes", len(out))},
		{Key: "Size delta", Value: delta(len(src.Data), len(out))},
		{Key: "Input SHA-256", Value: sha256Hex(src.Data)},
		{Key: "Output SHA-256", Value: sha256Hex(out)},
		{Key: "Verification", Value: verification},
		{Key: "Output file", Value: path},
	}
	fields = append(fields, paddingFields(padResult)...)
	a.summary(fields)
	return nil
}

func readTransformKey(hexKey, hexFile string) ([]byte, error) {
	if hexKey != "" && hexFile != "" {
		return nil, bferrors.New(bferrors.Usage, "--key and --key-file are mutually exclusive")
	}
	if hexKey == "" && hexFile == "" {
		return nil, bferrors.New(bferrors.Usage, "transform requires --key HEX or --key-file FILE")
	}
	if hexKey != "" {
		key, err := bytesutil.ParseHex(hexKey)
		if err != nil {
			return nil, bferrors.Wrap(bferrors.Usage, err, "invalid --key")
		}
		return key, nil
	}
	data, err := input.ReadPath(hexFile, 1<<20)
	if err != nil {
		return nil, err
	}
	key, err := bytesutil.ParseHex(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Usage, err, "invalid key in %s", hexFile)
	}
	return key, nil
}

// ---------------------------------------------------------------- inspect

type inspectContainerJSON struct {
	Version       byte   `json:"version"`
	CipherID      byte   `json:"cipherId"`
	Cipher        string `json:"cipher"`
	KDFID         byte   `json:"kdfId"`
	KDF           string `json:"kdf"`
	SaltLen       int    `json:"saltLen"`
	NonceLen      int    `json:"nonceLen"`
	Nonce         string `json:"nonce"`
	CiphertextLen uint64 `json:"ciphertextLen"`
	TagLen        int    `json:"tagLen"`
	TotalSize     int    `json:"totalSize"`
}

type inspectJSON struct {
	Path      string                `json:"path"`
	Size      int64                 `json:"size"`
	SHA256    string                `json:"sha256"`
	Entropy   float64               `json:"entropyBitsPerByte"`
	Container *inspectContainerJSON `json:"container,omitempty"`
}

func (a *App) cmdInspect(args []string) error {
	var f struct {
		input inputFlags
		json  bool
	}
	fs := a.newFlagSet("inspect", inspectUsage)
	a.registerCommon(fs)
	a.registerInputFlags(fs, &f.input)
	fs.BoolVar(&f.json, "json", false, "emit JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}
	src, err := a.loadInput(&f.input)
	if err != nil {
		return err
	}
	info, err := inspect.Analyze(src.Label, src.Data, int(a.common.MaxInput))
	if err != nil {
		return err
	}

	var out []byte
	if f.json {
		doc := inspectJSON{
			Path:    info.Path,
			Size:    info.Size,
			SHA256:  info.SHA256,
			Entropy: info.Entropy,
		}
		if info.Container != nil {
			ci := info.Container
			cipherName := "unknown"
			if c, ok := cryptography.ByID(ci.CipherID); ok {
				cipherName = c.Info().Name
			}
			doc.Container = &inspectContainerJSON{
				Version:       ci.Version,
				CipherID:      ci.CipherID,
				Cipher:        cipherName,
				KDFID:         ci.KDFID,
				KDF:           cryptography.KDFName(ci.KDFID),
				SaltLen:       ci.SaltLen,
				NonceLen:      ci.NonceLen,
				Nonce:         ci.NonceHex,
				CiphertextLen: ci.CiphertextLen,
				TagLen:        ci.TagLen,
				TotalSize:     ci.TotalSize,
			}
		}
		out, err = json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return bferrors.Wrap(bferrors.Processing, err, "encoding inspection JSON")
		}
		out = append(out, '\n')
	} else {
		out = []byte(a.formatInspection(info))
		a.rep.Preview("Input", src.Data)
	}

	path, err := a.writeOutput(out)
	if err != nil {
		return err
	}
	if path != "stdout" {
		a.rep.OK("inspection written to %s", path)
	}
	return nil
}

func (a *App) formatInspection(info *inspect.Info) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ByteForge inspection\n")
	fmt.Fprintf(&b, "  %-15s : %s\n", "Path", info.Path)
	fmt.Fprintf(&b, "  %-15s : %d bytes\n", "Size", info.Size)
	fmt.Fprintf(&b, "  %-15s : %s\n", "SHA-256", info.SHA256)
	fmt.Fprintf(&b, "  %-15s : %.4f bits/byte (descriptive only)\n", "Entropy", info.Entropy)
	if info.Container == nil {
		fmt.Fprintf(&b, "  %-15s : none (not a BFRG container)\n", "Container")
		return b.String()
	}
	ci := info.Container
	cipherName := "unknown"
	if c, ok := cryptography.ByID(ci.CipherID); ok {
		cipherName = c.Info().Name
	}
	fmt.Fprintf(&b, "  %-15s : BFRG v%d\n", "Container", ci.Version)
	fmt.Fprintf(&b, "  %-15s : %s (id %d)\n", "Cipher", cipherName, ci.CipherID)
	fmt.Fprintf(&b, "  %-15s : %s (id %d)\n", "KDF", cryptography.KDFName(ci.KDFID), ci.KDFID)
	fmt.Fprintf(&b, "  %-15s : %d bytes\n", "Salt", ci.SaltLen)
	fmt.Fprintf(&b, "  %-15s : %d bytes (%s)\n", "Nonce", ci.NonceLen, ci.NonceHex)
	fmt.Fprintf(&b, "  %-15s : %d bytes\n", "Ciphertext", ci.CiphertextLen)
	fmt.Fprintf(&b, "  %-15s : %d bytes\n", "Tag", ci.TagLen)
	return b.String()
}

// ---------------------------------------------------------------- verify

func (a *App) cmdVerify(args []string) error {
	var f struct {
		original  string
		recovered string
		file      string
		sha256    string
	}
	fs := a.newFlagSet("verify", verifyUsage)
	a.registerCommon(fs)
	fs.StringVar(&f.original, "original", "", "original file")
	fs.StringVar(&f.recovered, "recovered", "", "recovered file")
	fs.StringVar(&f.file, "file", "", "file to hash")
	fs.StringVar(&f.sha256, "sha256", "", "expected SHA-256")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}

	fileMode := f.file != "" || f.sha256 != ""
	compareMode := f.original != "" || f.recovered != ""
	if fileMode && compareMode {
		return bferrors.New(bferrors.Usage, "choose either --original/--recovered or --file/--sha256, not both")
	}

	var b strings.Builder
	passed := false
	switch {
	case compareMode:
		if f.original == "" || f.recovered == "" {
			return bferrors.New(bferrors.Usage, "verify requires both --original and --recovered")
		}
		orig, err := input.ReadPath(f.original, a.common.MaxInput)
		if err != nil {
			return err
		}
		rec, err := input.ReadPath(f.recovered, a.common.MaxInput)
		if err != nil {
			return err
		}
		passed = bytes.Equal(orig, rec)
		fmt.Fprintf(&b, "Verification      : %s\n", passLabel(passed))
		fmt.Fprintf(&b, "Original size     : %d bytes\n", len(orig))
		fmt.Fprintf(&b, "Recovered size    : %d bytes\n", len(rec))
		fmt.Fprintf(&b, "Original SHA-256  : %s\n", sha256Hex(orig))
		fmt.Fprintf(&b, "Recovered SHA-256 : %s\n", sha256Hex(rec))
	case fileMode:
		if f.file == "" || f.sha256 == "" {
			return bferrors.New(bferrors.Usage, "verify requires both --file and --sha256")
		}
		data, err := input.ReadPath(f.file, a.common.MaxInput)
		if err != nil {
			return err
		}
		got := sha256Hex(data)
		passed = strings.EqualFold(got, strings.TrimSpace(f.sha256))
		fmt.Fprintf(&b, "Verification      : %s\n", passLabel(passed))
		fmt.Fprintf(&b, "Size              : %d bytes\n", len(data))
		fmt.Fprintf(&b, "SHA-256           : %s\n", got)
		fmt.Fprintf(&b, "Expected SHA-256  : %s\n", strings.TrimSpace(f.sha256))
	default:
		return bferrors.New(bferrors.Usage, "verify requires --original/--recovered or --file/--sha256")
	}

	path, err := a.writeOutput([]byte(b.String()))
	if err != nil {
		return err
	}
	if path != "stdout" {
		a.rep.OK("verification report written to %s", path)
	}
	if !passed {
		return bferrors.New(bferrors.Verification, "verification FAILED")
	}
	return nil
}

func passLabel(ok bool) string {
	if ok {
		return "PASSED"
	}
	return "FAILED"
}

// ---------------------------------------------------------------- version

func (a *App) cmdVersion(args []string) error {
	fs := a.newFlagSet("version", "Usage: byteforge version [--verbose]\n")
	verbose := false
	fs.BoolVar(&verbose, "verbose", false, "include build details")
	fs.BoolVar(&verbose, "v", false, "include build details")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return errHelp
		}
		return bferrors.New(bferrors.Usage, "%s", err)
	}
	if verbose {
		fmt.Fprint(a.Stdout, version.Full())
	} else {
		fmt.Fprintf(a.Stdout, "byteforge %s\n", version.Version)
	}
	return nil
}
