// Package padding implements explicit, caller-selected padding for payloads
// before encoding, encryption, or transformation.
//
// Padding is never implicit. A caller must request a mode, and the CLI reports
// how many bytes were added. This package does not remove padding on the
// reverse path: padding changes the payload, so reverse operations only see
// whatever bytes were originally passed in.
package padding

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
)

// Kind identifies a padding fill strategy.
type Kind int

const (
	// None performs no padding and rejects misaligned input.
	None Kind = iota
	// NOP fills with 0x90.
	NOP
	// Zero fills with 0x00.
	Zero
	// Random fills from crypto/rand.
	Random
	// Pattern repeats a caller-supplied byte pattern.
	Pattern
)

// Mode is a parsed padding specification.
type Mode struct {
	Kind    Kind
	Pattern []byte
}

// ModeChoices is the canonical list shown in help and error messages.
const ModeChoices = "none, nop (0x90), zero (0x00), random (crypto/rand), or hex bytes such as CC or 9090"

// Parse parses a padding mode. The accepted values are "none", "nop", "zero",
// "random", or an even-length hexadecimal string of one or more bytes.
func Parse(spec string) (Mode, error) {
	switch spec {
	case "none":
		return Mode{Kind: None}, nil
	case "nop":
		return Mode{Kind: NOP}, nil
	case "zero":
		return Mode{Kind: Zero}, nil
	case "random":
		return Mode{Kind: Random}, nil
	}
	if spec == "" {
		return Mode{}, bferrors.New(bferrors.Usage, "empty padding mode; use %s", ModeChoices)
	}
	if len(spec)%2 != 0 {
		return Mode{}, bferrors.New(bferrors.Usage,
			"invalid --pad value %q: hexadecimal padding must contain whole bytes (use %s)", spec, ModeChoices)
	}
	pattern, err := hex.DecodeString(spec)
	if err != nil || len(pattern) == 0 {
		return Mode{}, bferrors.New(bferrors.Usage,
			"invalid --pad value %q: expected %s", spec, ModeChoices)
	}
	return Mode{Kind: Pattern, Pattern: pattern}, nil
}

// String returns a short human-readable label for reports.
func (m Mode) String() string {
	switch m.Kind {
	case None:
		return "none"
	case NOP:
		return "nop (0x90)"
	case Zero:
		return "zero (0x00)"
	case Random:
		return "random"
	case Pattern:
		return "hex " + strings.ToUpper(hex.EncodeToString(m.Pattern))
	default:
		return "unknown"
	}
}

// Method returns the compact method label used in encode padding warnings.
func (m Mode) Method() string {
	switch m.Kind {
	case None:
		return "none"
	case NOP:
		return "nop/0x90"
	case Zero:
		return "zero/0x00"
	case Random:
		return "random"
	case Pattern:
		return "hex/" + strings.ToUpper(hex.EncodeToString(m.Pattern))
	default:
		return "unknown"
	}
}

// Result describes the outcome of Apply.
type Result struct {
	Data     []byte
	Multiple int
	Added    int
	Mode     Mode
}

// Summary returns a concise report value.
func (r Result) Summary() string {
	if r.Added == 0 {
		if r.Mode.Kind == None {
			return fmt.Sprintf("none (input is a multiple of %d bytes)", r.Multiple)
		}
		return fmt.Sprintf("%s (already aligned to %d-byte multiple)", r.Mode, r.Multiple)
	}
	return fmt.Sprintf("%s (+%d bytes to %d-byte multiple)", r.Mode, r.Added, r.Multiple)
}

// Fill returns n bytes of the mode's fill pattern.
func Fill(n int, mode Mode) ([]byte, error) {
	if n < 0 {
		return nil, bferrors.New(bferrors.Usage, "padding length must not be negative, got %d", n)
	}
	fill := make([]byte, n)
	switch mode.Kind {
	case NOP:
		for i := range fill {
			fill[i] = 0x90
		}
	case Zero:
		// Zero values are already zero.
	case Random:
		if _, err := rand.Read(fill); err != nil {
			return nil, bferrors.Wrap(bferrors.Processing, err, "generating random padding")
		}
	case Pattern:
		for i := range fill {
			fill[i] = mode.Pattern[i%len(mode.Pattern)]
		}
	default:
		return nil, bferrors.New(bferrors.Usage, "padding mode %s cannot generate fill bytes", mode)
	}
	return fill, nil
}

// Apply pads data to the next multiple of multiple bytes.
//
// For Mode None it returns an error when the input is misaligned and leaves
// aligned input unchanged. Other modes add between 1 and multiple-1 bytes; an
// already aligned payload is never padded with a full extra block.
func Apply(data []byte, multiple int, mode Mode) (Result, error) {
	if multiple < 1 {
		return Result{}, bferrors.New(bferrors.Usage, "padding multiple must be at least 1 byte, got %d", multiple)
	}
	result := Result{Data: data, Multiple: multiple, Mode: mode}
	remainder := len(data) % multiple
	if remainder == 0 {
		return result, nil
	}
	if mode.Kind == None {
		return result, bferrors.New(bferrors.Usage,
			"input length %d is not a multiple of %d bytes (%d-byte remainder); use --pad nop|zero|random|HEX to pad",
			len(data), multiple, remainder)
	}

	need := multiple - remainder
	fill, err := Fill(need, mode)
	if err != nil {
		return Result{}, err
	}

	out := make([]byte, len(data)+need)
	copy(out, data)
	copy(out[len(data):], fill)
	result.Data = out
	result.Added = need
	return result, nil
}
