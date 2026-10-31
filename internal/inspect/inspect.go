// Package inspect analyzes input and encrypted containers without executing or
// interpreting the data as code.
//
// Entropy is reported as a descriptive statistic only. It is not evidence of
// safety, correctness, or shellcode.
package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"math"

	"github.com/zoro/byteforge/internal/container"
)

// ContainerInfo is the non-secret header view of a ByteForge container.
type ContainerInfo struct {
	Version       byte
	CipherID      byte
	KDFID         byte
	SaltLen       int
	NonceLen      int
	NonceHex      string
	CiphertextLen uint64
	TagLen        int
	TotalSize     int
}

// Info is the result of inspecting a file.
type Info struct {
	Path      string
	Size      int64
	SHA256    string
	Entropy   float64
	Container *ContainerInfo
}

// Analyze inspects data. If data begins with the ByteForge magic, the
// container is strictly parsed; malformed containers return an error instead
// of silently falling back to generic inspection.
func Analyze(path string, data []byte, maxCiphertext int) (*Info, error) {
	sum := sha256.Sum256(data)
	info := &Info{
		Path:    path,
		Size:    int64(len(data)),
		SHA256:  hex.EncodeToString(sum[:]),
		Entropy: Entropy(data),
	}

	if !container.LooksLikeContainer(data) {
		return info, nil
	}

	parsed, err := container.Parse(data, maxCiphertext)
	if err != nil {
		return nil, err
	}
	info.Container = &ContainerInfo{
		Version:       parsed.Header.Version,
		CipherID:      parsed.Header.CipherID,
		KDFID:         parsed.Header.KDFID,
		SaltLen:       len(parsed.Header.Salt),
		NonceLen:      len(parsed.Header.Nonce),
		NonceHex:      hex.EncodeToString(parsed.Header.Nonce),
		CiphertextLen: parsed.Header.CiphertextLen,
		TagLen:        parsed.Header.TagLen,
		TotalSize:     parsed.TotalSize(),
	}
	return info, nil
}

// Entropy returns Shannon entropy in bits per byte.
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
