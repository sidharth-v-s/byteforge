package container

import (
	"bytes"
	"testing"

	"github.com/zoro/byteforge/internal/bferrors"
)

func TestEncodeRawLayout(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03, 0x04}
	ct := []byte("ciphertext")
	tag := []byte{0xaa, 0xbb}

	got := EncodeRaw(nonce, ct, tag)
	want := append(append(append([]byte{}, nonce...), ct...), tag...)
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeRaw = %x, want %x", got, want)
	}

	got = EncodeRaw(nonce, ct, nil)
	want = append(append([]byte{}, nonce...), ct...)
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeRaw without tag = %x, want %x", got, want)
	}
}

func TestSplitRawRoundTrip(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03, 0x04}
	ct := []byte("ciphertext")
	tag := []byte{0xaa, 0xbb}
	blob := EncodeRaw(nonce, ct, tag)

	gotNonce, gotCT, gotTag, err := SplitRaw(blob, len(nonce), len(tag))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotCT, ct) || !bytes.Equal(gotTag, tag) {
		t.Fatalf("SplitRaw = %x / %x / %x", gotNonce, gotCT, gotTag)
	}
}

func TestSplitRawWithoutTag(t *testing.T) {
	nonce := []byte{0x01, 0x02, 0x03, 0x04}
	ct := []byte("ciphertext")
	blob := EncodeRaw(nonce, ct, nil)

	gotNonce, gotCT, gotTag, err := SplitRaw(blob, len(nonce), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNonce, nonce) || !bytes.Equal(gotCT, ct) {
		t.Fatalf("SplitRaw = %x / %x", gotNonce, gotCT)
	}
	if len(gotTag) != 0 {
		t.Fatalf("tag = %x, want empty", gotTag)
	}
}

func TestSplitRawValidation(t *testing.T) {
	if _, _, _, err := SplitRaw([]byte("short"), 0, 0); err == nil {
		t.Fatal("accepted a zero nonce length")
	} else if bferrors.KindOf(err) != bferrors.Usage {
		t.Fatalf("zero nonce error kind = %v, want Usage", bferrors.KindOf(err))
	}
	if _, _, _, err := SplitRaw([]byte("short"), 4, -1); err == nil {
		t.Fatal("accepted a negative tag length")
	}
	if _, _, _, err := SplitRaw([]byte("abc"), 4, 0); err == nil {
		t.Fatal("accepted input shorter than the nonce")
	}
	if _, _, _, err := SplitRaw([]byte("abcd"), 4, 2); err == nil {
		t.Fatal("accepted input shorter than nonce plus tag")
	}
}

func TestSplitRawDoesNotParseAsContainer(t *testing.T) {
	// Raw payloads begin with the nonce/IV, not the BFRG magic, so the strict
	// container parser must reject them.
	blob := EncodeRaw([]byte("1234567890abcdef"), []byte("ciphertext"), nil)
	if LooksLikeContainer(blob) {
		t.Fatal("raw payload was mistaken for a container")
	}
	if _, err := Parse(blob, 1024); err == nil {
		t.Fatal("Parse accepted a raw payload")
	}
}
