package input

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoro/byteforge/internal/bferrors"
)

func TestLoadValidation(t *testing.T) {
	if _, err := Load(Options{}); err == nil || bferrors.KindOf(err) != bferrors.Usage {
		t.Fatalf("missing input: err = %v", err)
	}
	if _, err := Load(Options{File: "a", Hex: "00"}); err == nil || bferrors.KindOf(err) != bferrors.Usage {
		t.Fatalf("conflicting input: err = %v", err)
	}
}

func TestLoadHex(t *testing.T) {
	src, err := Load(Options{Hex: "0x48 65:6c-6c_6f"})
	if err != nil {
		t.Fatal(err)
	}
	if string(src.Data) != "Hello" {
		t.Fatalf("got %q", src.Data)
	}
	if src.Label != "hex string" {
		t.Fatalf("label = %q", src.Label)
	}

	for _, bad := range []string{"abc", "zz", ""} {
		if _, err := Load(Options{Hex: bad}); err == nil {
			t.Fatalf("accepted hex %q", bad)
		}
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.bin")
	want := []byte{0x00, 0x01, 0xff}
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := Load(Options{File: path})
	if err != nil {
		t.Fatal(err)
	}
	if string(src.Data) != string(want) || src.Label != path {
		t.Fatalf("unexpected source: %+v", src)
	}

	empty := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err = Load(Options{File: empty})
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Data) != 0 {
		t.Fatal("empty file was not preserved as empty")
	}
}

func TestLoadFileErrors(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope")
	if _, err := Load(Options{File: missing}); err == nil || bferrors.KindOf(err) != bferrors.IO {
		t.Fatalf("missing file: err = %v", err)
	}
	if _, err := Load(Options{File: dir}); err == nil || bferrors.KindOf(err) != bferrors.IO {
		t.Fatalf("directory: err = %v", err)
	}

	large := filepath.Join(dir, "large.bin")
	if err := os.WriteFile(large, make([]byte, 128), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{File: large, MaxBytes: 64}); err == nil || bferrors.KindOf(err) != bferrors.IO {
		t.Fatalf("oversized file: err = %v", err)
	}
}

func TestMaxInputHex(t *testing.T) {
	if _, err := Load(Options{Hex: "0011223344", MaxBytes: 4}); err == nil {
		t.Fatal("accepted oversized hex input")
	}
}

func TestReadPathLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	if err := os.WriteFile(path, make([]byte, 10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPath(path, 5); err == nil {
		t.Fatal("ReadPath ignored limit")
	}
	if _, err := ReadPath(path, 10); err != nil {
		t.Fatalf("ReadPath rejected exact-limit file: %v", err)
	}
}
