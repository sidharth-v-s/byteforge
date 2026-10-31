package padding

import (
	"bytes"
	"testing"

	"github.com/zoro/byteforge/internal/bferrors"
)

func TestParseModes(t *testing.T) {
	cases := []struct {
		spec string
		kind Kind
	}{
		{"none", None},
		{"nop", NOP},
		{"zero", Zero},
		{"random", Random},
		{"CC", Pattern},
		{"9090", Pattern},
	}
	for _, tc := range cases {
		mode, err := Parse(tc.spec)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.spec, err)
		}
		if mode.Kind != tc.kind {
			t.Fatalf("Parse(%q) kind = %v, want %v", tc.spec, mode.Kind, tc.kind)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, spec := range []string{"", "no", "C", "zz", "0x90"} {
		if _, err := Parse(spec); err == nil {
			t.Fatalf("Parse(%q) succeeded", spec)
		} else if bferrors.KindOf(err) != bferrors.Usage {
			t.Fatalf("Parse(%q) error kind = %v", spec, bferrors.KindOf(err))
		}
	}
}

func TestApplyNoPaddingWhenAligned(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	for _, spec := range []string{"none", "nop", "zero", "random", "CC"} {
		mode, err := Parse(spec)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Apply(data, 4, mode)
		if err != nil {
			t.Fatalf("%s: %v", spec, err)
		}
		if result.Added != 0 {
			t.Fatalf("%s added %d bytes to aligned data", spec, result.Added)
		}
		if !bytes.Equal(result.Data, data) {
			t.Fatalf("%s changed aligned data", spec)
		}
	}
}

func TestApplyNoneRejectsMisalignment(t *testing.T) {
	mode, err := Parse("none")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Apply([]byte{1, 2, 3}, 4, mode)
	if err == nil {
		t.Fatal("accepted misaligned input")
	}
	if bferrors.KindOf(err) != bferrors.Usage {
		t.Fatalf("error kind = %v", bferrors.KindOf(err))
	}
}

func TestApplyFillModes(t *testing.T) {
	data := []byte{1, 2, 3}
	cases := []struct {
		spec string
		want []byte
	}{
		{"nop", []byte{1, 2, 3, 0x90}},
		{"zero", []byte{1, 2, 3, 0x00}},
		{"CC", []byte{1, 2, 3, 0xCC}},
		{"9090", []byte{1, 2, 3, 0x90}},
	}
	for _, tc := range cases {
		mode, err := Parse(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		result, err := Apply(data, 4, mode)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		if !bytes.Equal(result.Data, tc.want) {
			t.Fatalf("%s = %x, want %x", tc.spec, result.Data, tc.want)
		}
		if result.Added != 1 {
			t.Fatalf("%s added %d bytes, want 1", tc.spec, result.Added)
		}
	}
}

func TestApplyPatternRepeatsAndTruncates(t *testing.T) {
	mode, err := Parse("AABB")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply([]byte{0}, 6, mode)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA}
	if !bytes.Equal(result.Data, want) {
		t.Fatalf("padded = %x, want %x", result.Data, want)
	}
}

func TestApplyRandomAddsRequestedLength(t *testing.T) {
	mode, err := Parse("random")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Apply([]byte{1, 2, 3, 4, 5}, 8, mode)
	if err != nil {
		t.Fatal(err)
	}
	if result.Added != 3 {
		t.Fatalf("added %d bytes, want 3", result.Added)
	}
	if !bytes.Equal(result.Data[:5], []byte{1, 2, 3, 4, 5}) {
		t.Fatal("original bytes changed")
	}
}

func TestApplyRejectsInvalidMultiple(t *testing.T) {
	mode, _ := Parse("zero")
	if _, err := Apply([]byte{1}, 0, mode); err == nil {
		t.Fatal("accepted multiple 0")
	}
}

func TestFill(t *testing.T) {
	nop, _ := Parse("nop")
	got, err := Fill(3, nop)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0x90, 0x90, 0x90}) {
		t.Fatalf("Fill(nop) = %x", got)
	}
	zero, _ := Parse("zero")
	got, err = Fill(2, zero)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0, 0}) {
		t.Fatalf("Fill(zero) = %x", got)
	}
	pattern, _ := Parse("AABB")
	got, err = Fill(5, pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0xAA, 0xBB, 0xAA, 0xBB, 0xAA}) {
		t.Fatalf("Fill(AABB) = %x", got)
	}
	none, _ := Parse("none")
	if _, err := Fill(1, none); err == nil {
		t.Fatal("Fill(none) succeeded")
	}
}

func TestSummary(t *testing.T) {
	none, _ := Parse("none")
	nop, _ := Parse("nop")

	aligned := Result{Mode: none, Multiple: 4}
	if got, want := aligned.Summary(), "none (input is a multiple of 4 bytes)"; got != want {
		t.Fatalf("none summary = %q, want %q", got, want)
	}
	added := Result{Mode: nop, Multiple: 8, Added: 3}
	if got, want := added.Summary(), "nop (0x90) (+3 bytes to 8-byte multiple)"; got != want {
		t.Fatalf("nop summary = %q, want %q", got, want)
	}
	unchanged := Result{Mode: nop, Multiple: 8}
	if got, want := unchanged.Summary(), "nop (0x90) (already aligned to 8-byte multiple)"; got != want {
		t.Fatalf("aligned summary = %q, want %q", got, want)
	}
}
