package container

import "github.com/zoro/byteforge/internal/bferrors"

// Raw output layout used by --no-container:
//
//	nonce/IV (cipher.NonceSize) || ciphertext || tag (cipher.TagSize, omitted when 0)
//
// The layout carries no algorithm identifier, KDF salt, or length fields. The
// caller must know the cipher and provide the key explicitly.
//
// EncodeRaw serializes those components without interpreting them.
func EncodeRaw(nonce, ciphertext, tag []byte) []byte {
	out := make([]byte, 0, len(nonce)+len(ciphertext)+len(tag))
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	out = append(out, tag...)
	return out
}

// SplitRaw splits a raw payload into its nonce/IV, ciphertext, and tag. The
// returned slices alias data. tag is empty when tagLen is 0.
func SplitRaw(data []byte, nonceLen, tagLen int) (nonce, ciphertext, tag []byte, err error) {
	if nonceLen <= 0 {
		return nil, nil, nil, bferrors.New(bferrors.Usage, "raw payload requires a positive nonce/IV length, got %d", nonceLen)
	}
	if tagLen < 0 {
		return nil, nil, nil, bferrors.New(bferrors.Usage, "raw payload tag length must not be negative, got %d", tagLen)
	}
	if len(data) < nonceLen+tagLen {
		return nil, nil, nil, bferrors.New(bferrors.Processing,
			"raw payload is %d bytes, need at least %d for the nonce/IV and tag", len(data), nonceLen+tagLen)
	}
	nonce = data[:nonceLen]
	if tagLen > 0 {
		tag = data[len(data)-tagLen:]
		ciphertext = data[nonceLen : len(data)-tagLen]
	} else {
		ciphertext = data[nonceLen:]
	}
	return nonce, ciphertext, tag, nil
}
