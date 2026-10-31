package container

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func newTestHeader(t *testing.T) (*Header, []byte, []byte) {
	t.Helper()
	salt := bytes.Repeat([]byte{0xaa}, 16)
	nonce := bytes.Repeat([]byte{0xbb}, 12)
	h, err := NewHeader(1, 1, salt, nonce, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return h, salt, nonce
}

func TestRoundTrip(t *testing.T) {
	h, salt, nonce := newTestHeader(t)
	ct := bytes.Repeat([]byte{0xcc}, 10)
	tag := bytes.Repeat([]byte{0xdd}, 16)
	blob, err := h.Encode(ct, tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != HeaderSize+16+12+10+16 {
		t.Fatalf("unexpected size %d", len(blob))
	}

	p, err := Parse(blob, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if p.Header.Version != Version || p.Header.CipherID != 1 || p.Header.KDFID != 1 {
		t.Fatalf("header mismatch: %+v", p.Header)
	}
	if !bytes.Equal(p.Header.Salt, salt) || !bytes.Equal(p.Header.Nonce, nonce) {
		t.Fatal("salt/nonce mismatch")
	}
	if !bytes.Equal(p.Ciphertext, ct) || !bytes.Equal(p.Tag, tag) {
		t.Fatal("ciphertext/tag mismatch")
	}
	if !bytes.Equal(p.AAD(nil), h.AAD(nil)) {
		t.Fatal("AAD mismatch between writer and parser")
	}
	if !bytes.Equal(p.Fixed, blob[:HeaderSize]) {
		t.Fatal("fixed header mismatch")
	}
}

func TestAADIncludesExtra(t *testing.T) {
	h, _, _ := newTestHeader(t)
	extra := []byte("context")
	base := h.AAD(nil)
	full := h.AAD(extra)
	if !bytes.Equal(full[:len(base)], base) {
		t.Fatal("AAD does not start with header prefix")
	}
	if !bytes.Equal(full[len(base):], extra) {
		t.Fatal("AAD extra data mismatch")
	}
}

func TestEncodeLengthValidation(t *testing.T) {
	h, _, _ := newTestHeader(t)
	if _, err := h.Encode(make([]byte, 9), make([]byte, 16)); err == nil {
		t.Fatal("accepted short ciphertext")
	}
	if _, err := h.Encode(make([]byte, 10), make([]byte, 15)); err == nil {
		t.Fatal("accepted short tag")
	}
}

func TestNewHeaderValidation(t *testing.T) {
	nonce := make([]byte, 12)
	cases := []struct {
		name  string
		salt  []byte
		nonce []byte
		ct    int
		tag   int
	}{
		{"salt too large", make([]byte, MaxSalt+1), nonce, 0, 16},
		{"missing nonce", nil, nil, 0, 16},
		{"nonce too large", nil, make([]byte, MaxNonce+1), 0, 16},
		{"zero tag", nil, nonce, 0, 0},
		{"tag too large", nil, nonce, 0, MaxTag + 1},
		{"negative ct", nil, nonce, -1, 16},
	}
	for _, tc := range cases {
		if _, err := NewHeader(1, 0, tc.salt, tc.nonce, tc.ct, tc.tag); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

func TestParseRejectsBadMagic(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	blob[0] = 'X'
	if _, err := Parse(blob, 1024); err == nil {
		t.Fatal("accepted bad magic")
	}
}

func TestParseRejectsUnknownVersion(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	blob[4] = 99
	if _, err := Parse(blob, 1024); err == nil {
		t.Fatal("accepted unknown version")
	}
}

func TestParseRejectsFlagsAndReserved(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	withFlags := append([]byte(nil), blob...)
	withFlags[7] = 1
	if _, err := Parse(withFlags, 1024); err == nil {
		t.Fatal("accepted nonzero flags")
	}
	withReserved := append([]byte(nil), blob...)
	withReserved[11] = 1
	if _, err := Parse(withReserved, 1024); err == nil {
		t.Fatal("accepted nonzero reserved byte")
	}
}

func TestParseRejectsTruncation(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	for _, n := range []int{0, 1, HeaderSize - 1, HeaderSize, HeaderSize + 5, len(blob) - 1} {
		if _, err := Parse(blob[:n], 1024); err == nil {
			t.Fatalf("accepted truncated container of %d bytes", n)
		}
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	blob = append(blob, 0)
	if _, err := Parse(blob, 1024); err == nil {
		t.Fatal("accepted trailing data")
	}
}

func TestParseRejectsOversizedLength(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	binary.BigEndian.PutUint64(blob[12:20], 1<<40)
	if _, err := Parse(blob, 1024); err == nil {
		t.Fatal("accepted oversized ciphertext length")
	}
}

func TestParseRejectsFieldBounds(t *testing.T) {
	h, _, _ := newTestHeader(t)
	blob, _ := h.Encode(make([]byte, 10), make([]byte, 16))
	for _, tc := range []struct {
		name string
		off  int
		val  byte
	}{
		{"salt too large", 8, MaxSalt + 1},
		{"nonce zero", 9, 0},
		{"nonce too large", 9, MaxNonce + 1},
		{"tag zero", 10, 0},
		{"tag too large", 10, MaxTag + 1},
	} {
		mut := append([]byte(nil), blob...)
		mut[tc.off] = tc.val
		if _, err := Parse(mut, 1024); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

func TestLooksLikeContainer(t *testing.T) {
	if !LooksLikeContainer([]byte("BFRG\x01")) {
		t.Fatal("expected magic match")
	}
	if LooksLikeContainer([]byte("BFR")) || LooksLikeContainer([]byte("NOPE")) {
		t.Fatal("unexpected magic match")
	}
}
