package fsutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zoro/byteforge/internal/bferrors"
)

func TestWriteFileNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := WriteFile(path, []byte{1, 2, 3}, false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1 {
		t.Fatalf("got %x", got)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteFileRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := WriteFile(path, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	err := WriteFile(path, []byte("second"), false)
	if err == nil {
		t.Fatal("overwrote without force")
	}
	if bferrors.KindOf(err) != bferrors.IO {
		t.Fatalf("kind = %v, want IO", bferrors.KindOf(err))
	}
	got, _ := os.ReadFile(path)
	if string(got) != "first" {
		t.Fatal("original contents were modified")
	}
}

func TestWriteFileForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	if err := WriteFile(path, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("second"), true); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("got %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestWriteFileMissingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "out.bin")
	if err := WriteFile(path, []byte("x"), false); err == nil {
		t.Fatal("wrote into a missing directory")
	}
	if err := WriteFile(path, []byte("x"), true); err == nil {
		t.Fatal("atomic write into a missing directory succeeded")
	}
}
