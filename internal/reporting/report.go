// Package reporting renders human-readable diagnostics to stderr.
//
// Payload bytes are written by the CLI to stdout or a file; all status,
// progress, and summary text goes through this package to stderr so raw binary
// output is never polluted.
package reporting

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

// Field is one summary line.
type Field struct {
	Key   string
	Value string
}

// Reporter writes status messages.
type Reporter struct {
	w         io.Writer
	verbose   bool
	noColor   bool
	noBanner  bool
	timestamp bool
}

// New creates a reporter writing to w (normally stderr).
func New(w io.Writer) *Reporter {
	return &Reporter{w: w}
}

// Configure applies CLI display options.
func (r *Reporter) Configure(verbose, noColor, noBanner, timestamp bool) {
	r.verbose = verbose
	r.noColor = noColor
	r.noBanner = noBanner
	r.timestamp = timestamp
}

// Verbose reports whether verbose mode is enabled.
func (r *Reporter) Verbose() bool { return r.verbose }

// Timestamp reports whether timestamps are enabled.
func (r *Reporter) Timestamp() bool { return r.timestamp }

// IsTerminal reports whether w looks like a character device.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (r *Reporter) paint(code, text string) string {
	if r.noColor || !IsTerminal(r.w) {
		return text
	}
	return code + text + ansiReset
}

func (r *Reporter) line(tag, color, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(r.w, "%s %s\n", r.paint(color, tag), msg)
}

// Banner prints the startup banner unless suppressed.
func (r *Reporter) Banner() {
	if r.noBanner {
		return
	}
	fmt.Fprint(r.w, r.paint(ansiCyan, `
  ____        _       _____
 | __ ) _   _| |_ ___|  ___|__  _ __ __ _  ___
 |  _ \| | | | __/ _ \ |_ / _ \| '__/ _`+"`"+` |/ _ \
 | |_) | |_| | ||  __/  _| (_) | | | (_| |  __/
 |____/ \__, |\__\___|_|  \___/|_|  \__, |\___|
        |___/                       |___/
`))
}

// Info prints a routine status line.
func (r *Reporter) Info(format string, args ...any) { r.line("[*]", ansiCyan, format, args...) }

// OK prints a success line.
func (r *Reporter) OK(format string, args ...any) { r.line("[+]", ansiGreen, format, args...) }

// Warn prints a warning line.
func (r *Reporter) Warn(format string, args ...any) { r.line("[!]", ansiYellow, format, args...) }

// Error prints an error line.
func (r *Reporter) Error(format string, args ...any) { r.line("[ERROR]", ansiRed, format, args...) }

// Debug prints a diagnostic line only in verbose mode.
func (r *Reporter) Debug(format string, args ...any) {
	if !r.verbose {
		return
	}
	r.line("[DBG]", ansiGray, format, args...)
}

// Section prints a verbose section heading.
func (r *Reporter) Section(title string) {
	if !r.verbose {
		return
	}
	width := 54 - len(title)
	if width < 0 {
		width = 0
	}
	bar := strings.Repeat("─", width)
	fmt.Fprintf(r.w, "\n%s %s\n", r.paint(ansiBold, "── "+title), r.paint(ansiGray, bar))
}

// Preview prints a bounded hex preview. It never dumps full content.
func (r *Reporter) Preview(label string, data []byte) {
	if !r.verbose {
		return
	}
	const rows = 4
	const cols = 16
	limit := rows * cols
	shown := data
	if len(shown) > limit {
		shown = shown[:limit]
	}
	fmt.Fprintf(r.w, "  %s (%d bytes, first %d):\n", label, len(data), len(shown))
	for i := 0; i < len(shown); i += cols {
		end := i + cols
		if end > len(shown) {
			end = len(shown)
		}
		var hexPart strings.Builder
		var ascii strings.Builder
		for j := i; j < end; j++ {
			fmt.Fprintf(&hexPart, "%02X ", shown[j])
			if shown[j] >= 32 && shown[j] < 127 {
				ascii.WriteByte(shown[j])
			} else {
				ascii.WriteByte('.')
			}
		}
		fmt.Fprintf(r.w, "    %04X  %-48s  %s\n", i, hexPart.String(), ascii.String())
	}
	if len(data) > limit {
		fmt.Fprintf(r.w, "    ... (%d more bytes)\n", len(data)-limit)
	}
}

// Summary prints the final report block.
func (r *Reporter) Summary(fields []Field) {
	bar := strings.Repeat("-", 60)
	fmt.Fprintln(r.w, bar)
	for _, f := range fields {
		fmt.Fprintf(r.w, "  %-15s : %s\n", f.Key, f.Value)
	}
	fmt.Fprintln(r.w, bar)
}
