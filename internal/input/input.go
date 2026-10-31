// Package input loads binary-safe input from a file or hexadecimal string.
//
// There is intentionally no built-in default payload. Omitting both --file and
// --hex is a usage error.
package input

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/bytesutil"
)

// DefaultMaxBytes is the documented default input limit (64 MiB).
const DefaultMaxBytes int64 = 64 << 20

// Options controls input loading.
type Options struct {
	File     string
	Hex      string
	MaxBytes int64
}

// Source is loaded input with a non-secret label for reports.
type Source struct {
	Data  []byte
	Label string
}

// Load reads input according to opts. Exactly one of File or Hex must be set.
func Load(opts Options) (*Source, error) {
	if opts.File != "" && opts.Hex != "" {
		return nil, bferrors.New(bferrors.Usage, "--file and --hex are mutually exclusive")
	}
	if opts.File == "" && opts.Hex == "" {
		return nil, bferrors.New(bferrors.Usage, "no input specified: provide --file FILE or --hex HEX")
	}

	max := opts.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if opts.File != "" {
		data, err := readFile(opts.File, max)
		if err != nil {
			return nil, err
		}
		return &Source{Data: data, Label: opts.File}, nil
	}

	data, err := bytesutil.ParseHex(opts.Hex)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Usage, err, "invalid --hex input")
	}
	if int64(len(data)) > max {
		return nil, bferrors.New(bferrors.Usage, "hex input is %d bytes, exceeding the %d-byte limit", len(data), max)
	}
	return &Source{Data: data, Label: "hex string"}, nil
}

func readFile(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, bferrors.Wrap(bferrors.IO, err, "input file not found: %s", path)
		}
		return nil, bferrors.Wrap(bferrors.IO, err, "cannot stat input file %s", path)
	}
	if info.IsDir() {
		return nil, bferrors.New(bferrors.IO, "input path is a directory, not a file: %s", path)
	}
	if info.Size() > max {
		return nil, bferrors.New(bferrors.IO, "input file %s is %d bytes, exceeding the %d-byte limit (use --max-input to raise it)",
			path, info.Size(), max)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, bferrors.Wrap(bferrors.IO, err, "cannot open input file %s", path)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.IO, err, "reading input file %s", path)
	}
	if int64(len(data)) > max {
		return nil, bferrors.New(bferrors.IO, "input file %s exceeds the %d-byte limit (use --max-input to raise it)", path, max)
	}
	return data, nil
}

// ReadPath reads a file with the same limit semantics as Load. It is used by
// commands that take explicit paths (verify) rather than --file/--hex.
func ReadPath(path string, max int64) ([]byte, error) {
	if max <= 0 {
		max = DefaultMaxBytes
	}
	return readFile(path, max)
}

// Describe returns a human-readable label for a path without leaking content.
func Describe(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// FormatSize renders a byte count with a short binary unit suffix.
func FormatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
