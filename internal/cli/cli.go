// Package cli implements the ByteForge command-line interface.
//
// Exit codes follow the specification:
//
//	0 success
//	1 general processing failure
//	2 invalid arguments or unsupported option
//	3 input/output failure
//	4 verification or authentication failure
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/codec"
	"github.com/zoro/byteforge/internal/fsutil"
	"github.com/zoro/byteforge/internal/input"
	"github.com/zoro/byteforge/internal/inspect"
	"github.com/zoro/byteforge/internal/padding"
	"github.com/zoro/byteforge/internal/pipeline"
	"github.com/zoro/byteforge/internal/registry"
	"github.com/zoro/byteforge/internal/renderer"
	"github.com/zoro/byteforge/internal/reporting"
	"github.com/zoro/byteforge/internal/version"
)

var errHelp = errors.New("help requested")

// App holds process-wide CLI state for one invocation.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader

	rep    *reporting.Reporter
	common commonFlags

	stdoutPayload       bool
	payloadTailsNewline bool
}

type commonFlags struct {
	Verbose   bool
	NoColor   bool
	NoBanner  bool
	Force     bool
	Timestamp bool
	Output    string
	MaxInput  int64
}

type inputFlags struct {
	file string
	hex  string
}

type renderFlags struct {
	name   string
	symbol string
	bpl    int
	pad    string
	padTo  int
}

// Run executes a CLI invocation using os.Stdin.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithIO(args, os.Stdin, stdout, stderr)
}

// RunWithIO executes a CLI invocation with an explicit stdin (used by tests).
func RunWithIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a := &App{Stdout: stdout, Stderr: stderr, Stdin: stdin}
	a.rep = reporting.New(stderr)
	a.prescan(args)
	a.rep.Configure(a.common.Verbose, a.common.NoColor, a.common.NoBanner, a.common.Timestamp)

	if len(args) == 0 {
		fmt.Fprint(stderr, rootUsage)
		return 2
	}

	var err error
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, rootUsage)
		return 0
	case "version", "--version":
		err = a.cmdVersion(args[1:])
	case "formats":
		err = a.cmdFormats(args[1:])
	case "encode":
		err = a.cmdEncode(args[1:])
	case "decode":
		err = a.cmdDecode(args[1:])
	case "encrypt":
		err = a.cmdEncrypt(args[1:])
	case "decrypt":
		err = a.cmdDecrypt(args[1:])
	case "transform":
		err = a.cmdTransform(args[1:], "transform")
	case "untransform":
		err = a.cmdTransform(args[1:], "untransform")
	case "inspect":
		err = a.cmdInspect(args[1:])
	case "verify":
		err = a.cmdVerify(args[1:])
	default:
		err = bferrors.New(bferrors.Usage, "unknown command %q (run 'byteforge help')", args[0])
	}

	if err != nil {
		if errors.Is(err, errHelp) {
			return 0
		}
		a.rep.Error("%s", err)
		return bferrors.ExitCode(err)
	}
	return 0
}

// prescan configures display options early so parse failures are reported with
// the requested color/banner settings.
func (a *App) prescan(args []string) {
	for _, arg := range args {
		switch arg {
		case "-v", "--verbose":
			a.common.Verbose = true
		case "--no-color":
			a.common.NoColor = true
		case "--no-banner":
			a.common.NoBanner = true
		case "--timestamp":
			a.common.Timestamp = true
		}
	}
}

func (a *App) configure() {
	a.rep.Configure(a.common.Verbose, a.common.NoColor, a.common.NoBanner, a.common.Timestamp)
}

func (a *App) newFlagSet(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { fmt.Fprint(a.Stdout, usage) }
	return fs
}

func (a *App) parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(normalizeOptionalPad(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelp
		}
		return flagParseError(fs, err)
	}
	a.configure()
	if a.common.MaxInput <= 0 {
		return bferrors.New(bferrors.Usage, "--max-input must be greater than zero")
	}
	return nil
}

func (a *App) registerCommon(fs *flag.FlagSet) {
	fs.BoolVar(&a.common.Verbose, "verbose", false, "verbose diagnostics")
	fs.BoolVar(&a.common.Verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&a.common.NoColor, "no-color", false, "disable ANSI color")
	fs.BoolVar(&a.common.NoBanner, "no-banner", false, "suppress startup banner")
	fs.BoolVar(&a.common.Force, "force", false, "overwrite an existing output file")
	fs.BoolVar(&a.common.Timestamp, "timestamp", false, "include a timestamp in reports")
	fs.StringVar(&a.common.Output, "output", "", "write payload to FILE instead of stdout")
	fs.StringVar(&a.common.Output, "o", "", "shorthand for --output")
	fs.Int64Var(&a.common.MaxInput, "max-input", input.DefaultMaxBytes, "maximum input size in bytes")
}

func (a *App) registerInputFlags(fs *flag.FlagSet, f *inputFlags) {
	fs.StringVar(&f.file, "file", "", "read input from FILE")
	fs.StringVar(&f.file, "f", "", "shorthand for --file")
	fs.StringVar(&f.hex, "hex", "", "read input from a hexadecimal string")
	fs.StringVar(&f.hex, "s", "", "shorthand for --hex")
}

func (a *App) registerRenderFlags(fs *flag.FlagSet, r *renderFlags) {
	fs.StringVar(&r.name, "renderer", "raw", "output renderer (see 'byteforge formats')")
	fs.StringVar(&r.symbol, "symbol", "data", "symbol name for data-declaration renderers")
	fs.IntVar(&r.bpl, "bytes-per-line", 16, "bytes per line for array renderers")
	fs.StringVar(&r.pad, "pad", "", "pad payload before the operation: none|nop|zero|random|HEX (default: random when enabled)")
	fs.IntVar(&r.padTo, "pad-to", -1, "padding multiple in bytes (default: fixed codec width or 16)")
}

// normalizeOptionalPad makes a bare --pad mean --pad=random. A missing value is
// therefore not an error for this flag; --pad with an invalid value still is.
func normalizeOptionalPad(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--pad" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				out = append(out, "--pad=random")
				continue
			}
		}
		out = append(out, args[i])
	}
	return out
}

func (a *App) loadInput(f *inputFlags) (*input.Source, error) {
	return input.Load(input.Options{File: f.file, Hex: f.hex, MaxBytes: a.common.MaxInput})
}

func validateRender(r *renderFlags) error {
	if _, ok := renderer.Get(r.name); !ok {
		return unknownName("renderer", r.name, renderer.Names())
	}
	if r.bpl < 1 || r.bpl > 256 {
		return bferrors.New(bferrors.Usage, "--bytes-per-line must be between 1 and 256, got %d", r.bpl)
	}
	if r.padTo != -1 && (r.padTo < 1 || r.padTo > 1<<20) {
		return bferrors.New(bferrors.Usage, "--pad-to must be between 1 and 1048576, got %d", r.padTo)
	}
	if r.pad != "" {
		if _, err := padding.Parse(r.pad); err != nil {
			return err
		}
	}
	return nil
}

// paddingFields returns summary rows for an applied padding result.
func paddingFields(result *padding.Result) []reporting.Field {
	if result == nil || result.Added == 0 {
		return nil
	}
	return []reporting.Field{
		{Key: "Padding", Value: result.Summary()},
		{Key: "Padded payload", Value: fmt.Sprintf("%d bytes", len(result.Data))},
	}
}

// encodePadding applies the encode-specific padding contract.
//
// Padding is meaningful only for fixed-width codecs. For a single-value codec,
// it fills a short input up to the exact width and rejects oversized input
// before padding. For a list codec, it fills the final partial chunk. Other
// codecs ignore padding with a warning.
func (a *App) encodePadding(data []byte, r *renderFlags, codecName string) ([]byte, *padding.Result, error) {
	if r.pad == "" && r.padTo == -1 {
		return data, nil, nil
	}

	chunk, isList := codec.FixedWidth(codecName)
	exact, isExact := codec.ExactWidth(codecName)
	if !isList && !isExact {
		if r.pad != "" {
			a.rep.Warn("--pad has no effect for encoding '%s'; ignoring", codecName)
		}
		if r.padTo != -1 {
			a.rep.Warn("--pad-to has no effect for encoding '%s'; ignoring", codecName)
		}
		return data, nil, nil
	}
	if isExact {
		chunk = exact
	}

	spec := r.pad
	if spec == "" {
		spec = "random"
	}
	mode, err := padding.Parse(spec)
	if err != nil {
		return nil, nil, err
	}

	if r.padTo != -1 && r.padTo != chunk {
		unit := "values"
		if isList {
			unit = "chunks"
		}
		return nil, nil, bferrors.New(bferrors.Usage,
			"--pad-to %d is incompatible with %s, which uses %d-byte %s",
			r.padTo, codecName, chunk, unit)
	}

	if isExact && len(data) > chunk {
		count := (len(data) + chunk - 1) / chunk
		hint := ""
		if list := codec.ListCodec(codecName); list != "" {
			if mode.Kind == padding.None {
				hint = fmt.Sprintf("\n        Use --encoding %s to encode as a sequence of %d %s.",
					list, count, codecUnit(codecName))
			} else {
				hint = fmt.Sprintf("\n        Use --encoding %s --pad %s to encode as a sequence of %d %s.",
					list, spec, count, codecUnit(codecName))
			}
		}
		return nil, nil, bferrors.New(bferrors.Usage,
			"%s requires exactly %d bytes, got %d; --pad cannot truncate data.%s",
			codecName, chunk, len(data), hint)
	}

	if isExact && len(data) == 0 && mode.Kind != padding.None {
		fill, err := padding.Fill(chunk, mode)
		if err != nil {
			return nil, nil, err
		}
		result := padding.Result{Data: fill, Multiple: chunk, Added: chunk, Mode: mode}
		a.rep.Warn("input 0 bytes padded by +%d bytes (%s) → total %d bytes (%s)",
			result.Added, mode.Method(), len(result.Data), chunksLabel(1))
		return fill, &result, nil
	}

	result, err := padding.Apply(data, chunk, mode)
	if err != nil {
		return nil, nil, err
	}

	chunks := len(result.Data) / chunk
	if result.Added == 0 {
		if isList {
			a.rep.Info("no padding needed (%d bytes, %s)", len(data), chunksLabel(chunks))
		} else {
			a.rep.Info("no padding needed")
		}
		return result.Data, &result, nil
	}

	a.rep.Warn("input %d bytes padded by +%d bytes (%s) → total %d bytes (%s)",
		len(data), result.Added, mode.Method(), len(result.Data), chunksLabel(chunks))
	return result.Data, &result, nil
}

func chunksLabel(n int) string {
	if n == 1 {
		return "1 chunk"
	}
	return fmt.Sprintf("%d chunks", n)
}

func codecUnit(name string) string {
	switch name {
	case "ipv4", "ipv6":
		return "addresses"
	case "mac":
		return "MAC addresses"
	case "uuid":
		return "UUIDs"
	default:
		return "values"
	}
}

// applyPadding enforces the requested padding before an operation. The target
// multiple is --pad-to when given, otherwise a fixed-width codec's element
// width, otherwise 16 bytes.
func (a *App) applyPadding(data []byte, r *renderFlags, codecName string) ([]byte, *padding.Result, error) {
	if r.pad == "" && r.padTo == -1 {
		return data, nil, nil
	}
	spec := r.pad
	if spec == "" {
		spec = "random"
	}
	mode, err := padding.Parse(spec)
	if err != nil {
		return nil, nil, err
	}
	multiple := r.padTo
	if width, ok := codec.ExactWidth(codecName); ok {
		if multiple > 0 && multiple != width {
			return nil, nil, bferrors.New(bferrors.Usage,
				"--pad-to %d is incompatible with %s, which accepts exactly %d bytes",
				multiple, codecName, width)
		}
		if len(data) > width {
			hint := ""
			if list := codec.ListCodec(codecName); list != "" {
				if mode.Kind == padding.None {
					hint = fmt.Sprintf("; use --encoding %s for a sequence", list)
				} else {
					hint = fmt.Sprintf("; use --encoding %s --pad %s for a sequence that fills the final partial value", list, spec)
				}
			}
			return nil, nil, bferrors.New(bferrors.Usage,
				"%s accepts exactly %d bytes, got %d%s (padding cannot split or repeat data)",
				codecName, width, len(data), hint)
		}
		multiple = width
	} else if multiple <= 0 {
		if width, ok := codec.FixedWidth(codecName); ok {
			multiple = width
		} else {
			multiple = 16
		}
	}
	result, err := padding.Apply(data, multiple, mode)
	if err != nil {
		return nil, nil, err
	}
	if result.Added == 0 {
		a.rep.Info("padding: %s; payload is already a multiple of %d bytes", mode, multiple)
	} else {
		a.rep.Info("padding: %s; added %d bytes to reach a %d-byte multiple", mode, result.Added, multiple)
	}
	return result.Data, &result, nil
}

func unknownName(kind, name string, names []string) error {
	return bferrors.New(bferrors.Usage, "unknown %s %q (available: %s)", kind, name, strings.Join(names, ", "))
}

// prepareOutput fails early when a non-forced output path already exists or
// its directory is missing.
func (a *App) prepareOutput() error {
	if a.common.Output == "" || a.common.Force {
		return nil
	}
	if fsutil.Exists(a.common.Output) {
		return bferrors.New(bferrors.IO, "output file already exists: %s (use --force to overwrite)", a.common.Output)
	}
	dir := filepath.Dir(a.common.Output)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return bferrors.New(bferrors.IO, "output directory does not exist: %s", dir)
		}
		return bferrors.Wrap(bferrors.IO, err, "cannot access output directory %s", dir)
	}
	return nil
}

func (a *App) writeOutput(data []byte) (string, error) {
	if a.common.Output == "" {
		if _, err := a.Stdout.Write(data); err != nil {
			return "", bferrors.Wrap(bferrors.IO, err, "writing to stdout")
		}
		if len(data) > 0 {
			a.stdoutPayload = true
			a.payloadTailsNewline = data[len(data)-1] == '\n'
		}
		return "stdout", nil
	}
	if err := fsutil.WriteFile(a.common.Output, data, a.common.Force); err != nil {
		return "", err
	}
	return a.common.Output, nil
}

func (a *App) emit(data []byte, rendererName string) (string, error) {
	if a.common.Output == "" && rendererName == "raw" && reporting.IsTerminal(a.Stdout) {
		a.rep.Warn("writing raw binary to a terminal; use --output FILE to avoid corrupting the display")
	}
	return a.writeOutput(data)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (a *App) meta(op, format, encoding, cipher, verification string, in []byte, r *renderFlags) registry.Meta {
	m := registry.Meta{
		Tool:         "byteforge",
		Version:      version.Version,
		Operation:    op,
		Format:       format,
		Encoding:     encoding,
		Cipher:       cipher,
		InputSize:    len(in),
		InputSHA256:  sha256Hex(in),
		Verification: verification,
		Symbol:       r.symbol,
		BytesPerLine: r.bpl,
	}
	if a.common.Timestamp {
		m.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	return m
}

func (a *App) summary(fields []reporting.Field) {
	// Text codecs such as ipv4-list deliberately omit a trailing newline, and
	// raw binary may end anywhere. Separate the summary from such stdout so it
	// does not run into the last payload line when both streams share a terminal.
	if a.stdoutPayload && !a.payloadTailsNewline {
		fmt.Fprint(a.Stderr, "\n\n")
	}
	if a.common.Timestamp {
		fields = append(fields, reporting.Field{Key: "Timestamp", Value: time.Now().UTC().Format(time.RFC3339)})
	}
	a.rep.Summary(fields)
}

func (a *App) verboseDetails(label string, data []byte, timings []pipeline.Timing) {
	if !a.rep.Verbose() {
		return
	}
	a.rep.Preview(label, data)
	a.rep.Debug("entropy: %.4f bits/byte (descriptive only)", inspect.Entropy(data))
	for _, t := range timings {
		a.rep.Debug("stage %-24s %s", t.Name, t.Duration.Round(time.Microsecond))
	}
}

func delta(in, out int) string {
	d := out - in
	if d >= 0 {
		return fmt.Sprintf("+%d bytes", d)
	}
	return fmt.Sprintf("%d bytes", d)
}
