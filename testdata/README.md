# ByteForge Test Vectors

These files are the published golden vectors for ByteForge 0.1.0. They are
verified by `go test ./...` and described in
[`docs/FORMATS.md`](../docs/FORMATS.md).

**Do not use these keys, passwords, nonces, or salts for real data.** They are
public test material.

## Files

```text
testdata/
├── codecs.json                 codec input/output vectors
├── plaintext/
│   └── ByteForge.bin           the 9-byte ASCII plaintext "ByteForge"
└── containers/
    ├── gcm-key.bf              AES-256-GCM, explicit key
    ├── gcm-key.hex             same container as hex text
    ├── gcm-key-aad.bf          AES-256-GCM with AAD "context=v1"
    ├── gcm-key-aad.hex
    ├── gcm128-key.bf           AES-128-GCM, explicit key
    ├── gcm128-key.hex
    ├── chacha-key.bf           ChaCha20-Poly1305, explicit key
    ├── chacha-key.hex
    ├── cbc-key.bf              AES-256-CBC + HMAC-SHA256, explicit key
    ├── cbc-key.hex
    ├── gcm-password.bf         AES-256-GCM, scrypt password, fixed salt
    └── gcm-password.hex
```

Every container encrypts the same plaintext, `ByteForge` (no newline).

## Parameters

Shared 32-byte key:

```text
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Shared 12-byte nonce:

```text
000102030405060708090a0b
```

Shared 16-byte nonce/IV:

```text
000102030405060708090a0b0c0d0e0f
```

| Vector | Cipher | Key | Nonce/IV | Extra |
| --- | --- | --- | --- | --- |
| `gcm-key.bf` | `aes-256-gcm` | 32-byte shared key | 12-byte shared nonce | none |
| `gcm-key-aad.bf` | `aes-256-gcm` | 32-byte shared key | 12-byte shared nonce | AAD `context=v1` |
| `gcm128-key.bf` | `aes-128-gcm` | `000102030405060708090a0b0c0d0e0f` | 12-byte shared nonce | none |
| `chacha-key.bf` | `chacha20-poly1305` | 32-byte shared key | 12-byte shared nonce | none |
| `cbc-key.bf` | `aes-256-cbc` | 32-byte shared key | 16-byte shared IV | none |
| `gcm-password.bf` | `aes-256-gcm` | scrypt of `correct horse battery staple` | 12-byte shared nonce | salt `101112131415161718191a1b1c1d1e1f` |

The password vector uses scrypt with the version-1 parameters
(N=2^15, r=8, p=1, dkLen=32, 16-byte salt). Its derived key is:

```text
4422cc8b14ecaf05e5b234429eac95c3594a6f75c9bdd032fedf5416db8dae48
```

## Using a vector

```bash
byteforge decrypt --file testdata/containers/gcm-key.bf \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --no-banner --output /tmp/ByteForge.bin

byteforge decrypt --file testdata/containers/gcm-key-aad.bf \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --aad 'context=v1' --no-banner --output /tmp/ByteForge.bin

printf 'correct horse battery staple\n' | \
  byteforge decrypt --file testdata/containers/gcm-password.bf \
  --password-stdin --no-banner --output /tmp/ByteForge.bin
```

`inspect` reports the header fields without any key:

```bash
byteforge inspect --file testdata/containers/gcm-password.bf --no-banner
```

## Codec vectors

`codecs.json` is a JSON array. Each entry has:

- `name`: codec identifier;
- `inputHex`: input bytes as hex;
- `encoded`: output text, present only when the output is valid UTF-8;
- `encodedHex`: output bytes as hex, always present.

This dual representation is necessary because `raw` and some escaped forms can
contain arbitrary bytes that JSON strings cannot represent faithfully.

## Changing vectors

Vectors are part of the compatibility contract. If a codec, cipher, container
field, KDF parameter, or renderer changes, update:

1. `testdata/` binary and hex files;
2. the expectations in `internal/cryptography/vectors_test.go` or
   `internal/codec/vectors_test.go`;
3. `docs/FORMATS.md` and this README.

A vector change must never be made merely to make a failing test pass. First
determine whether the change is a bug fix or an intentional format revision. An
intentional revision requires a new container version where applicable.
