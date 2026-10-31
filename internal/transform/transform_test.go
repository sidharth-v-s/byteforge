package transform

import (
	"bytes"
	"testing"
)

func TestXORSingleByteKnownVector(t *testing.T) {
	tr, _ := Get("xor-single-byte")
	in := []byte{0x00, 0xff, 0x41, 0x42}
	got, err := tr.Apply(in, []byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xaa, 0x55, 0xeb, 0xe8}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	back, err := tr.Apply(got, []byte{0xaa})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, in) {
		t.Fatal("single-byte XOR is not an involution")
	}
}

func TestXORRepeatingKeyKnownVector(t *testing.T) {
	tr, _ := Get("xor-repeating-key")
	in := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := tr.Apply(in, key)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xde, 0xad, 0xbe, 0xef, 0xde}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
	back, err := tr.Apply(got, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, in) {
		t.Fatal("repeating-key XOR is not an involution")
	}
}

func TestKeyValidation(t *testing.T) {
	single, _ := Get("xor-single-byte")
	rep, _ := Get("xor-repeating-key")
	if err := single.ValidateKey(nil); err == nil {
		t.Fatal("single accepted empty key")
	}
	if err := single.ValidateKey([]byte{1, 2}); err == nil {
		t.Fatal("single accepted two-byte key")
	}
	if err := rep.ValidateKey(nil); err == nil {
		t.Fatal("repeating accepted empty key")
	}
	if err := rep.ValidateKey(make([]byte, 257)); err == nil {
		t.Fatal("repeating accepted 257-byte key")
	}
	if err := rep.ValidateKey(make([]byte, 256)); err != nil {
		t.Fatalf("repeating rejected 256-byte key: %v", err)
	}
}

func TestEmptyInput(t *testing.T) {
	for _, name := range Names() {
		tr, _ := Get(name)
		key := []byte{0x01}
		out, err := tr.Apply(nil, key)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 0 {
			t.Fatalf("%s changed empty input", name)
		}
	}
}

func TestMetadata(t *testing.T) {
	for _, name := range Names() {
		tr, _ := Get(name)
		info := tr.Info()
		if info.Name != name || info.Security != "transform" || !info.Reversible {
			t.Fatalf("bad metadata for %s: %+v", name, info)
		}
		if info.Warning == "" {
			t.Fatalf("%s lacks a security warning", name)
		}
	}
}
