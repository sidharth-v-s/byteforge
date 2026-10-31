// Package container implements ByteForge's versioned encrypted-file format.
//
// The format is deliberately small and deterministic. A fixed 20-byte header
// carries the format identity, algorithm identifiers, KDF identifier, and
// lengths. Salt and nonce follow the header, then ciphertext, then the
// authentication tag. The fixed header, salt, and nonce are authenticated as
// associated data by the cipher, alongside any caller-supplied AAD.
//
// See docs/FORMATS.md for the byte-level specification and test vectors.
package container

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/zoro/byteforge/internal/bferrors"
)

const (
	// Magic identifies a ByteForge encrypted container.
	Magic = "BFRG"
	// Version is the current container version written by this release.
	Version byte = 1
	// HeaderSize is the fixed header length in bytes.
	HeaderSize = 20

	// MaxSalt, MaxNonce, and MaxTag bound variable-length fields before any
	// allocation is performed from file-controlled lengths.
	MaxSalt  = 64
	MaxNonce = 32
	MaxTag   = 64
)

// Header is the fixed portion of a container plus its variable salt/nonce.
type Header struct {
	Version       byte
	CipherID      byte
	KDFID         byte
	Flags         byte
	Salt          []byte
	Nonce         []byte
	CiphertextLen uint64
	TagLen        int
}

// NewHeader validates and constructs a version-1 header.
func NewHeader(cipherID, kdfID byte, salt, nonce []byte, ciphertextLen, tagLen int) (*Header, error) {
	if ciphertextLen < 0 {
		return nil, bferrors.New(bferrors.Processing, "invalid ciphertext length %d", ciphertextLen)
	}
	if len(salt) > MaxSalt {
		return nil, bferrors.New(bferrors.Processing, "salt is too large (%d bytes, max %d)", len(salt), MaxSalt)
	}
	if len(nonce) == 0 || len(nonce) > MaxNonce {
		return nil, bferrors.New(bferrors.Processing, "invalid nonce length %d (max %d)", len(nonce), MaxNonce)
	}
	if tagLen <= 0 || tagLen > MaxTag {
		return nil, bferrors.New(bferrors.Processing, "invalid tag length %d (max %d)", tagLen, MaxTag)
	}
	return &Header{
		Version:       Version,
		CipherID:      cipherID,
		KDFID:         kdfID,
		Flags:         0,
		Salt:          append([]byte(nil), salt...),
		Nonce:         append([]byte(nil), nonce...),
		CiphertextLen: uint64(ciphertextLen),
		TagLen:        tagLen,
	}, nil
}

// fixed encodes the 20-byte fixed header.
func (h *Header) fixed() []byte {
	b := make([]byte, HeaderSize)
	copy(b[0:4], Magic)
	b[4] = h.Version
	b[5] = h.CipherID
	b[6] = h.KDFID
	b[7] = h.Flags
	b[8] = byte(len(h.Salt))
	b[9] = byte(len(h.Nonce))
	b[10] = byte(h.TagLen)
	b[11] = 0 // reserved
	binary.BigEndian.PutUint64(b[12:20], h.CiphertextLen)
	return b
}

// prefix returns header || salt || nonce.
func (h *Header) prefix() []byte {
	f := h.fixed()
	out := make([]byte, 0, len(f)+len(h.Salt)+len(h.Nonce))
	out = append(out, f...)
	out = append(out, h.Salt...)
	out = append(out, h.Nonce...)
	return out
}

// AAD returns the authenticated associated data for this header.
func (h *Header) AAD(extra []byte) []byte {
	p := h.prefix()
	out := make([]byte, 0, len(p)+len(extra))
	out = append(out, p...)
	out = append(out, extra...)
	return out
}

// Encode serializes the full container. It verifies that ciphertext and tag
// lengths match the header so a malformed header cannot be emitted.
func (h *Header) Encode(ciphertext, tag []byte) ([]byte, error) {
	if uint64(len(ciphertext)) != h.CiphertextLen {
		return nil, bferrors.New(bferrors.Processing,
			"ciphertext length %d does not match header length %d", len(ciphertext), h.CiphertextLen)
	}
	if len(tag) != h.TagLen {
		return nil, bferrors.New(bferrors.Processing,
			"tag length %d does not match header length %d", len(tag), h.TagLen)
	}
	p := h.prefix()
	out := make([]byte, 0, len(p)+len(ciphertext)+len(tag))
	out = append(out, p...)
	out = append(out, ciphertext...)
	out = append(out, tag...)
	return out, nil
}

// Parsed is a fully validated container split into its fields. Ciphertext and
// Tag alias the input buffer; callers must not mutate the input while using
// them.
type Parsed struct {
	Header     *Header
	Fixed      []byte
	AADPrefix  []byte
	Ciphertext []byte
	Tag        []byte
}

// AAD returns the authenticated associated data, optionally with extra data.
func (p *Parsed) AAD(extra []byte) []byte {
	out := make([]byte, 0, len(p.AADPrefix)+len(extra))
	out = append(out, p.AADPrefix...)
	out = append(out, extra...)
	return out
}

// TotalSize returns the exact serialized size.
func (p *Parsed) TotalSize() int {
	return len(p.AADPrefix) + len(p.Ciphertext) + len(p.Tag)
}

// LooksLikeContainer reports whether data begins with the ByteForge magic.
func LooksLikeContainer(data []byte) bool {
	return len(data) >= len(Magic) && string(data[:len(Magic)]) == Magic
}

// Parse strictly parses and validates a container. maxCiphertext bounds the
// file-controlled ciphertext length before allocation or slicing; pass 0 to
// bound only by the input size.
func Parse(data []byte, maxCiphertext int) (*Parsed, error) {
	if len(data) < HeaderSize {
		return nil, bferrors.New(bferrors.Processing,
			"truncated container: %d bytes, need at least %d", len(data), HeaderSize)
	}
	if !bytes.Equal(data[0:4], []byte(Magic)) {
		return nil, bferrors.New(bferrors.Processing, "not a ByteForge container (bad magic)")
	}
	version := data[4]
	if version != Version {
		return nil, bferrors.New(bferrors.Processing,
			"unsupported container version %d (this build supports version %d)", version, Version)
	}
	cipherID := data[5]
	kdfID := data[6]
	flags := data[7]
	if flags != 0 {
		return nil, bferrors.New(bferrors.Processing, "unsupported container flags 0x%02x", flags)
	}
	saltLen := int(data[8])
	nonceLen := int(data[9])
	tagLen := int(data[10])
	if data[11] != 0 {
		return nil, bferrors.New(bferrors.Processing, "invalid container: reserved header byte is nonzero")
	}
	if saltLen > MaxSalt {
		return nil, bferrors.New(bferrors.Processing, "invalid container: salt length %d exceeds %d", saltLen, MaxSalt)
	}
	if nonceLen == 0 || nonceLen > MaxNonce {
		return nil, bferrors.New(bferrors.Processing, "invalid container: nonce length %d", nonceLen)
	}
	if tagLen <= 0 || tagLen > MaxTag {
		return nil, bferrors.New(bferrors.Processing, "invalid container: tag length %d", tagLen)
	}
	ctLen64 := binary.BigEndian.Uint64(data[12:20])
	if maxCiphertext > 0 && ctLen64 > uint64(maxCiphertext) {
		return nil, bferrors.New(bferrors.Processing,
			"container ciphertext length %d exceeds configured limit %d", ctLen64, maxCiphertext)
	}
	if ctLen64 > uint64(len(data)) {
		return nil, bferrors.New(bferrors.Processing,
			"truncated container: declared ciphertext length %d exceeds input size %d", ctLen64, len(data))
	}
	ctLen := int(ctLen64)

	need := HeaderSize + saltLen + nonceLen + ctLen + tagLen
	if len(data) < need {
		return nil, bferrors.New(bferrors.Processing,
			"truncated container: have %d bytes, need %d", len(data), need)
	}
	if len(data) > need {
		return nil, bferrors.New(bferrors.Processing,
			"invalid container: %d trailing bytes", len(data)-need)
	}

	off := HeaderSize
	salt := data[off : off+saltLen]
	off += saltLen
	nonce := data[off : off+nonceLen]
	off += nonceLen
	ct := data[off : off+ctLen]
	off += ctLen
	tag := data[off : off+tagLen]

	h := &Header{
		Version:       version,
		CipherID:      cipherID,
		KDFID:         kdfID,
		Flags:         flags,
		Salt:          append([]byte(nil), salt...),
		Nonce:         append([]byte(nil), nonce...),
		CiphertextLen: ctLen64,
		TagLen:        tagLen,
	}
	fixed := append([]byte(nil), data[:HeaderSize]...)
	prefix := append([]byte(nil), data[:HeaderSize+saltLen+nonceLen]...)

	return &Parsed{
		Header:     h,
		Fixed:      fixed,
		AADPrefix:  prefix,
		Ciphertext: ct,
		Tag:        tag,
	}, nil
}

// Describe returns a short non-secret description for reports.
func (p *Parsed) Describe() string {
	return fmt.Sprintf("BFRG v%d, cipher id %d, kdf id %d", p.Header.Version, p.Header.CipherID, p.Header.KDFID)
}
