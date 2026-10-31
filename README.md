# ByteForge

ByteForge is a binary transformation and inspection tool written in Go. It encodes, encrypts,
renders, inspects, and verifies data through separate, explicit stages. It is inspired by the
workflow of `aes_encryptor.py`, but keeps **encoding**, **encryption**, and **output rendering**
distinct so each stage is predictable and reversible on its own.

ByteForge is a single, self-contained native binary. It does not require Python, a runtime, or a
network connection.

> **Safety boundary:** ByteForge transforms data only. It never executes, loads, injects, or
> delivers processed bytes. Generated language output (C, C#, Nim, Go, Python, PowerShell, VBA,
> VBS, Rust, JavaScript, and Zig) is a data declaration only, never a loader. There is no built-in
> payload and no implicit default key.

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Build from source](#build-from-source)
  - [Static binary](#static-binary)
  - [Cross-compilation](#cross-compilation)
  - [Version injection](#version-injection)
- [Quick start](#quick-start)
- [How the stages fit together](#how-the-stages-fit-together)
- [Command reference](#command-reference)
  - [`formats`](#formats)
  - [`encode`](#encode)
  - [`decode`](#decode)
  - [`encrypt`](#encrypt)
  - [`decrypt`](#decrypt)
  - [`transform` / `untransform`](#transform--untransform)
  - [`inspect`](#inspect)
  - [`verify`](#verify)
  - [`version`](#version)
- [Common options](#common-options)
- [Supported formats](#supported-formats)
  - [Representation codecs](#representation-codecs)
  - [Reversible transforms](#reversible-transforms)
  - [Ciphers](#ciphers)
  - [Renderers](#renderers)
- [Key handling](#key-handling)
- [Padding](#padding)
- [Container format](#container-format)
- [Output behavior](#output-behavior)
- [Exit codes](#exit-codes)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Design decisions and limitations](#design-decisions-and-limitations)
- [Documentation](#documentation)

---

## Features

- **Binary-safe pipelines.** Input and output are handled as raw bytes; encoding and rendering
  never alter data implicitly.
- **Separate stages.** Codecs (representation), ciphers (confidentiality), transforms
  (obfuscation), and renderers (output syntax) are independent registries.
- **Authenticated encryption by default.** AES-256-GCM is the default; AES-128-GCM and
  ChaCha20-Poly1305 are also available.
- **Strict, self-describing containers.** Encrypted data uses the versioned `BFRG` v1 format,
  authenticated end to end.
- **Lossless typed codecs.** MAC, IPv4, IPv6, UUID, and their `-list` variants round-trip exactly
  or fail with a clear error — no guessing, no silent truncation.
- **Explicit padding only.** `--pad` is opt-in, reported in diagnostics, and never inferred.
- **Eleven language renderers plus JSON.** Data-only declarations are available for C, C#, Nim,
  Go, Python, PowerShell, VBA, VBS, Rust, JavaScript, and Zig; `json` wraps Base64 data and
  metadata. None of them emit loader code.
- **Inspection and verification.** Size, SHA-256, entropy, container metadata, file comparison, and
  digest checks.
- **Script-friendly.** Status goes to stderr, payload goes to stdout, exit codes are classified,
  and `formats --json` / `inspect --json` provide machine-readable output.
- **Portable static builds.** Pure Go, `CGO_ENABLED=0`, cross-compiles to Linux, Windows, and macOS.

## Requirements

- **Go 1.25 or newer** to build from source.
- No runtime dependencies beyond the operating system.
- The only direct module dependency is `golang.org/x/crypto` (scrypt and ChaCha20-Poly1305).

## Installation

### Build from source

```bash
git clone https://github.com/zoro/byteforge.git
cd byteforge
mkdir -p dist

# Run the test suite first
go test ./...

# Build the CLI
go build -trimpath -o dist/byteforge ./cmd/byteforge
```

Install it somewhere on your `PATH`:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 dist/byteforge "$HOME/.local/bin/byteforge"
byteforge version
```

On Windows the output is `dist\byteforge.exe`; add that directory to `PATH` instead of copying to
`~/.local/bin`.

### Static binary

ByteForge is pure Go and can be built without CGO. On Linux, a `CGO_ENABLED=0` build is statically
linked and does not depend on the target machine's libc, Go toolchain, or Python installation:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/byteforge ./cmd/byteforge
```

`-s -w` strips debug symbols and DWARF data to reduce size; it is optional. Verify the result:

```bash
file dist/byteforge
ldd dist/byteforge        # prints "not a dynamic executable" for a static build
./dist/byteforge version --verbose
```

A static binary is portable across machines with the same operating system and CPU architecture.
It is **not** portable across operating systems: a Linux binary does not run on Windows or macOS,
and vice versa. Build one binary per target.

### Cross-compilation

Build and test on the development platform first; cross-compile only for targets you can verify:

```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/byteforge-linux-amd64 ./cmd/byteforge
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/byteforge-linux-arm64 ./cmd/byteforge
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/byteforge-windows-amd64.exe ./cmd/byteforge
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/byteforge-darwin-arm64 ./cmd/byteforge
```

### Version injection

The release version defaults to the value in `internal/version`. Override it at link time:

```bash
go build -trimpath \
  -ldflags "-X github.com/sidharth-v-s/byteforge/internal/version.Version=0.1.0" \
  -o dist/byteforge ./cmd/byteforge
```

For a stripped static build:

```bash
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X github.com/sidharth-v-s/byteforge/internal/version.Version=0.1.0" \
  -o dist/byteforge ./cmd/byteforge
```

## Quick start

```bash
# List every supported format, grouped by category
byteforge formats

# Encode a binary file as Base64 text
byteforge encode --file input.bin --encoding base64 --output payload.txt

# Decode it again and verify the round trip
byteforge decode --file payload.txt --encoding base64 --output recovered.bin
byteforge verify --original input.bin --recovered recovered.bin

# Encrypt with a password read from stdin (recommended over --password)
printf 'correct horse battery staple' | \
  byteforge encrypt --file input.bin --password-stdin --output sample.bf

# Decrypt
printf 'correct horse battery staple' | \
  byteforge decrypt --file sample.bf --password-stdin --output recovered.bin

# Inspect the container header (non-secret metadata only)
byteforge inspect --file sample.bf

# Encrypt to a source file; the derived key is included automatically
printf 'correct horse battery staple' | \
  byteforge encrypt --file input.bin --password-stdin \
    --renderer javascript-array --output payload.js

# Render encoded bytes as a C data declaration
byteforge encode --file input.bin --encoding hex --renderer c-array \
  --symbol payload --output payload.c

# Other languages use the same data-only model
byteforge encode --file input.bin --encoding hex --renderer rust-array \
  --symbol PAYLOAD --output payload.rs
byteforge encode --file input.bin --encoding hex --renderer powershell-bytes \
  --symbol payload --output payload.ps1

# A single typed value requires the exact width
byteforge encode --file address.bin --encoding ipv4      # exactly 4 bytes
byteforge encode --file mac.bin     --encoding mac       # exactly 6 bytes
byteforge encode --file uuid.bin    --encoding uuid      # exactly 16 bytes

# Longer data: use a lossless sequence codec
byteforge encode --file calc.bin --encoding ipv4-list --output addresses.txt
byteforge decode --file addresses.txt --encoding ipv4-list --output recovered.bin
byteforge verify --original calc.bin --recovered recovered.bin

# Explicit padding for fixed-width codecs (276 -> 288 bytes, 18 chunks)
byteforge encode --file calc.bin --encoding ipv6-list --pad nop --output addresses.txt

# A short value is padded up to a single-value codec's exact width
byteforge encode --hex 20010db8 --encoding ipv6 --pad zero

# Bare --pad means random fill; --pad none only checks alignment
byteforge encode --hex 0001020304 --encoding ipv4-list --pad --output addresses.txt
byteforge encode --file mac.bin --encoding mac-list --pad none --output addresses.txt
```

## How the stages fit together

Every operation is an explicit chain. No stage is implied by another:

```text
input bytes
    │
    ├── encode ──> codec.Encode        (hex, base64, ipv4-list, …)
    │                  └──> renderer   (raw, c-array, rust-array, json, …)
    │
    ├── encrypt ─> container.Encrypt    (cipher + KDF + BFRG v1)
    │                  └──> renderer
    │
    ├── transform ─> XOR transform      (obfuscation only, not encryption)
    │                  └──> renderer
    │
    └── decode / decrypt / untransform  (strict reverse stage)
```

- **Codecs** change representation only. They are reversible and do not provide confidentiality.
- **Ciphers** change bytes and provide confidentiality/integrity. They are not text formats.
- **Transforms** are reversible XOR operations for educational use. They are not encryption.
- **Renderers** format bytes for display or embedding. They never execute the data.

Encryption output is a binary container unless a key-capable renderer is selected, in which case
the container bytes (and the key) are emitted as a language declaration.

## Command reference

Run `byteforge` with no arguments, `byteforge help`, or `byteforge <command> --help` for the same
information from the CLI.

### `formats`

```text
byteforge formats [--json] [--verbose] [--no-color]
```

Lists codecs, transforms, ciphers, and renderers in separate groups. `--json` emits a
machine-readable schema for tooling. `--verbose` includes parameters such as key sizes, nonce
sizes, and decode rules.

```bash
byteforge formats
byteforge formats --verbose
byteforge formats --json
```

### `encode`

```text
byteforge encode --encoding NAME [options]
```

Applies a representation codec and then a renderer.

| Option               | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| `--encoding NAME`    | Codec identifier (required)                                     |
| `--renderer NAME`    | Output renderer (default: `raw`)                                |
| `--symbol NAME`      | Symbol for data-declaration renderers (default: `data`)         |
| `--bytes-per-line N` | Bytes per line for array renderers (1–256, default 16)          |
| `--pad MODE`         | Pad fixed-width codecs (`none`, `nop`, `zero`, `random`, `HEX`) |
| `--pad-to N`         | Padding multiple; must match the codec width on `encode`        |
| `--no-verify`        | Skip the round-trip verification                                |

`--file` and `--hex` provide the input. Exactly one is required; there is no implicit default
payload and no implicit stdin fallback.

```bash
# Text encodings
byteforge encode --file input.bin --encoding base64 --output payload.txt
byteforge encode --hex 48656c6c6f --encoding hex --output payload.hex

# Typed single values
byteforge encode --hex c0a80101 --encoding ipv4
byteforge encode --hex 001122334455 --encoding mac
byteforge encode --hex 550e8400e29b41d4a716446655440000 --encoding uuid

# Typed sequences (lossless; no implicit padding)
byteforge encode --file calc.bin --encoding ipv4-list --output addresses.txt

# Source declarations
byteforge encode --file input.bin --encoding hex --renderer c-array \
  --symbol payload --output payload.c
byteforge encode --file input.bin --encoding base64 --renderer json \
  --output payload.json

# Machine-readable metadata
byteforge encode --file input.bin --encoding hex --renderer json --output payload.json
```

### `decode`

```text
byteforge decode --encoding NAME [options]
```

Reverses a representation codec and then renders the recovered bytes.

| Option            | Description                                                    |
| ----------------- | -------------------------------------------------------------- |
| `--encoding NAME` | Codec identifier (required)                                    |
| `--renderer NAME` | Output renderer (default: `raw`)                               |
| `--pad MODE`      | Pad the decoded bytes (`none`, `nop`, `zero`, `random`, `HEX`) |
| `--pad-to N`      | Padding multiple (default: codec width or 16)                  |
| `--no-verify`     | Skip the round-trip verification                               |

Decoding is strict. Invalid alphabets, bad group lengths, malformed addresses, and invalid
padding are errors, not best-effort guesses.

```bash
byteforge decode --file payload.txt --encoding base64 --output recovered.bin
byteforge decode --file addresses.txt --encoding ipv4-list --output recovered.bin
byteforge decode --file payload.hex --encoding hex
```

### `encrypt`

```text
byteforge encrypt [key source] [options]
```

Encrypts input into a versioned `BFRG` v1 container.

| Option                 | Description                                                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| `--cipher NAME`        | `aes-256-gcm` (default), `aes-128-gcm`, `chacha20-poly1305`, `aes-256-cbc`, `aes-256-ctr`, `rc4` |
| `--password TEXT`      | Password (visible in the process list; avoid)                                                    |
| `--password-file FILE` | Read the password from a file                                                                    |
| `--password-stdin`     | Read the password from stdin                                                                     |
| `--key HEX`            | Explicit key as hex (length depends on cipher)                                                   |
| `--key-file FILE`      | Read an explicit key as hex from a file                                                          |
| `--export-key FILE`    | Export the key (opt-in; contains a secret)                                                       |
| `--key-symbol NAME`    | Symbol for the rendered key declaration (default: `key`)                                         |
| `--nonce HEX`          | Explicit nonce/IV (tests and interoperability only)                                              |
| `--aad TEXT`           | Additional authenticated data (repeat at decrypt)                                                |
| `--allow-legacy`       | Permit legacy algorithms (currently `rc4`)                                                       |
| `--pad MODE`           | Pad the plaintext before encryption                                                              |
| `--pad-to N`           | Padding multiple (default: 16)                                                                   |
| `--no-verify`          | Skip the internal decrypt verification                                                           |

Choose exactly one key source: a password source or an explicit key. If neither is supplied,
ByteForge generates a random key. Key-capable renderers include the generated key automatically;
`raw`, `hex`, and `base64` require `--export-key FILE`.

```bash
# Password from stdin (recommended)
printf '%s' "$PASSWORD" | byteforge encrypt --file input.bin \
  --password-stdin --output sample.bf

# Explicit 32-byte key
byteforge encrypt --file input.bin \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --output sample.bf

# Generated key with export
byteforge encrypt --file input.bin --export-key sample.key --output sample.bf

# Additional authenticated data
byteforge encrypt --file input.bin --password-stdin \
  --aad "context=v1" --output sample.bf

# Directly usable source declaration (key included automatically)
printf '%s' "$PASSWORD" | byteforge encrypt --file input.bin \
  --password-stdin --renderer c-array --symbol payload --output payload.c
```

### `decrypt`

```text
byteforge decrypt [key source] [options]
```

Strictly parses a `BFRG` v1 container and decrypts it. Authentication is verified **before** any
plaintext is returned or written.

| Option                                              | Description                                |
| --------------------------------------------------- | ------------------------------------------ |
| `--password`, `--password-file`, `--password-stdin` | Password source                            |
| `--key HEX`, `--key-file FILE`                      | Explicit key source                        |
| `--aad TEXT`                                        | AAD used at encryption                     |
| `--allow-legacy`                                    | Permit legacy algorithms (currently `rc4`) |
| `--renderer NAME`                                   | Output renderer (default: `raw`)           |
| `--pad MODE`                                        | Pad the plaintext after decryption         |
| `--pad-to N`                                        | Padding multiple (default: 16)             |
| `--no-verify`                                       | Skip re-encryption verification            |

```bash
printf '%s' "$PASSWORD" | byteforge decrypt --file sample.bf \
  --password-stdin --output recovered.bin

byteforge decrypt --file sample.bf \
  --key 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --output recovered.bin
```

### `transform` / `untransform`

```text
byteforge transform --transform NAME --key HEX [options]
byteforge untransform --transform NAME --key HEX [options]
```

Applies a reversible XOR transform. XOR is symmetric, so `transform` and `untransform` perform the
same operation. XOR is **obfuscation, not encryption**.

| Option             | Description                                         |
| ------------------ | --------------------------------------------------- |
| `--transform NAME` | `xor-single-byte` or `xor-repeating-key` (required) |
| `--key HEX`        | Transform key (required; 1 byte or 1–256 bytes)     |
| `--key-file FILE`  | Read the transform key as hex from a file           |
| `--pad MODE`       | Pad the payload around the transform                |
| `--pad-to N`       | Padding multiple (default: 16)                      |
| `--renderer NAME`  | Output renderer (default: `raw`)                    |
| `--no-verify`      | Skip double-application verification                |

```bash
byteforge transform --file input.bin --transform xor-single-byte --key 5a
byteforge transform --file input.bin --transform xor-repeating-key --key deadbeef
```

### `inspect`

```text
byteforge inspect [-f FILE | -s HEX] [--json] [--verbose]
```

Reports size, SHA-256, entropy, and non-secret container metadata. If the input begins with the
ByteForge magic, the container is strictly parsed; malformed containers are reported as errors.

```bash
byteforge inspect --file sample.bf
byteforge inspect --file input.bin --verbose
byteforge inspect --file sample.bf --json
```

Entropy is a descriptive statistic. It is **not** evidence that data is encrypted, safe, or
correct.

### `verify`

```text
byteforge verify --original FILE --recovered FILE
byteforge verify --file FILE --sha256 HEX
```

Compares two files byte-for-byte, or verifies a file's SHA-256 digest (case-insensitive).

```bash
byteforge verify --original input.bin --recovered recovered.bin
byteforge verify --file sample.bf --sha256 9f86d081884c7d65...
```

### `version`

```text
byteforge version [--verbose]
```

Prints the version. `--verbose` adds build and platform details.

```bash
byteforge version
byteforge version --verbose
```

## Common options

These options are accepted by the data commands (`encode`, `decode`, `encrypt`, `decrypt`,
`transform`, `untransform`, and `inspect`) unless noted otherwise. Place them **after** the
subcommand. `verify`, `formats`, and `version` accept only the subset shown in their help.

| Option               | Description                                                             |
| -------------------- | ----------------------------------------------------------------------- |
| `-f, --file FILE`    | Read input from a file (binary-safe)                                    |
| `-s, --hex HEX`      | Read input from a hexadecimal string (mutually exclusive with `--file`) |
| `-o, --output FILE`  | Write the payload to a file (default: stdout)                           |
| `--force`            | Overwrite an existing output file                                       |
| `--renderer NAME`    | Output renderer (default: `raw`; see [`formats`](#formats))             |
| `--symbol NAME`      | Symbol for data-declaration renderers (default: `data`)                 |
| `--bytes-per-line N` | Bytes per line for array renderers (1–256, default 16)                  |
| `--pad MODE`         | Explicit padding: `none`, `nop`, `zero`, `random`, or `HEX`             |
| `--pad-to N`         | Padding multiple (1–1048576; default: codec width or 16)                |
| `--verbose, -v`      | Verbose diagnostics (never prints secrets)                              |
| `--no-color`         | Disable ANSI color                                                      |
| `--no-banner`        | Suppress the startup banner                                             |
| `--timestamp`        | Include a timestamp in reports                                          |
| `--max-input N`      | Maximum input bytes (default: 64 MiB)                                   |
| `--help`             | Show command help                                                       |

Behavior notes:

- If `--file` and `--hex` are both supplied, the invocation is rejected.
- If neither is supplied, the invocation is rejected with a usage error. There is no implicit
  default payload or stdin fallback.
- `--bytes-per-line` is rejected outside 1–256.
- `--max-input` must be greater than zero.
- Output files are never overwritten without `--force`.
- A flag given without a value produces an error naming the flag and listing accepted values.

## Supported formats

### Representation codecs

Codecs change representation only. They are reversible and provide no confidentiality.

| Identifier       | Input requirement | Notes                                       |
| ---------------- | ----------------- | ------------------------------------------- |
| `hex`            | any bytes         | Uppercase output; strict hexadecimal        |
| `base64`         | any bytes         | Standard alphabet, padding required         |
| `base64url`      | any bytes         | URL-safe alphabet, padding required         |
| `base32`         | any bytes         | RFC 4648; case-insensitive decoding         |
| `ascii85`        | any bytes         | Go standard library implementation          |
| `raw`            | any bytes         | Identity                                    |
| `mac`            | exactly 6 bytes   | EUI-48 form `AA:BB:CC:DD:EE:FF`             |
| `ipv4`           | exactly 4 bytes   | Dotted-quad text                            |
| `ipv6`           | exactly 16 bytes  | Canonical text                              |
| `uuid`           | exactly 16 bytes  | Canonical RFC 4122 text, network byte order |
| `mac-list`       | multiple of 6     | One MAC per line; lossless sequence         |
| `ipv4-list`      | multiple of 4     | One IPv4 address per line                   |
| `ipv6-list`      | multiple of 16    | One IPv6 address per line                   |
| `uuid-list`      | multiple of 16    | One UUID per line                           |
| `decimal`        | any bytes         | Space-separated values 0–255                |
| `octal`          | any bytes         | Three-digit octal groups                    |
| `binary`         | any bytes         | Eight-bit groups                            |
| `c-escaped`      | any bytes         | Quoted data-only C string                   |
| `unicode-escape` | any bytes         | `\u00HH` Latin-1 mapping                    |

Notes:

- Fixed-width single-value codecs reject every other length instead of guessing intent.
- `-list` codecs are the supported way to represent long data. They encode one value per line and
  decode whitespace, comma, or semicolon separators. Empty input is preserved.
- Hex decoding accepts whitespace, `:`, `-`, `,`, `_`, and `0x`/`\x` prefixes.
- Base32, Base64, and Base64URL decoding is case-insensitive where applicable and ignores ASCII
  whitespace, but padding remains strict.

### Reversible transforms

Grouped separately from cryptography because XOR is not encryption.

| Identifier          | Key            | Notes                                 |
| ------------------- | -------------- | ------------------------------------- |
| `xor-single-byte`   | exactly 1 byte | Obfuscation only                      |
| `xor-repeating-key` | 1–256 bytes    | Trivially breakable; obfuscation only |

### Ciphers

| Identifier          | Class                                  | Key (bytes) | Nonce/IV (bytes) | Tag (bytes) |
| ------------------- | -------------------------------------- | -----------:| ----------------:| -----------:|
| `aes-256-gcm`       | Authenticated (default)                | 32          | 12               | 16          |
| `aes-128-gcm`       | Authenticated                          | 16          | 12               | 16          |
| `chacha20-poly1305` | Authenticated                          | 32          | 12               | 16          |
| `aes-256-cbc`       | Compatibility (HMAC-SHA256)            | 32          | 16               | 32          |
| `aes-256-ctr`       | Compatibility (HMAC-SHA256)            | 32          | 16               | 32          |
| `rc4`               | Legacy (HMAC-SHA256; `--allow-legacy`) | 32          | 16               | 32          |

CBC and CTR are wrapped with encrypt-then-MAC using HKDF-SHA256-derived subkeys. Authentication is
verified before decryption. RC4 is obsolete and cannot be selected without `--allow-legacy`.

### Renderers

| Identifier         | Output                                 |
| ------------------ | -------------------------------------- |
| `raw`              | Exact bytes                            |
| `hex`              | Uppercase hex text                     |
| `base64`           | Standard Base64 text                   |
| `c-array`          | C/C++ `unsigned char` data declaration |
| `csharp-array`     | C# `byte[]` declaration                |
| `nim-array`        | Nim `array[N, byte]` declaration       |
| `go-bytes`         | Go `[]byte` literal                    |
| `python-bytes`     | Python bytes literal                   |
| `powershell-bytes` | PowerShell `[byte[]]` declaration      |
| `vba-array`        | VBA `Byte` array initialization        |
| `vbs-array`        | VBScript `Array` declaration           |
| `rust-array`       | Rust `[u8; N]` array                   |
| `javascript-array` | JavaScript `Uint8Array` declaration    |
| `zig-array`        | Zig `[_]u8` array                      |
| `json`             | JSON schema 1.0 with Base64 data       |

All language renderers are data declarations only. They accept `--symbol` and `--bytes-per-line`
and never emit loaders, imports, allocation helpers, or execution code.

On `encrypt`, every key-capable renderer also emits a second declaration named `key` (change it
with `--key-symbol`). `json` adds a `key` object with Base64 data. `raw`, `hex`, and `base64`
cannot carry two values in one stream, so they never include a key; use `--export-key FILE` when
you need a separate key.

## Key handling

Key sources are explicit and mutually exclusive:

- **Passwords:** `--password`, `--password-file FILE`, or `--password-stdin`.
- **Explicit keys:** `--key HEX` or `--key-file FILE`.

If neither is supplied during encryption, a random key is generated. With a key-capable renderer
it is included in the output automatically; with `raw`, `hex`, or `base64`, `--export-key FILE` is
required so the ciphertext is not left unrecoverable.

Password-based encryption uses scrypt (N=2^15, r=8, p=1, 16-byte salt) and derives the selected
cipher's key size: 32 bytes for AES-256 and ChaCha20-Poly1305, 16 bytes for AES-128-GCM. The salt
is stored in the container.

Keys are never printed in summaries or diagnostic text. They appear only in the payload of
key-capable renderers or an explicitly requested `--export-key` file. Exported key files are
written with mode `0600` and trigger a secret-material warning.

Encryption with a key-capable renderer always embeds the actual key used by the cipher, so the
ciphertext and key can be pasted into the same source file. This covers the data-declaration
renderers (`c-array`, `csharp-array`, `nim-array`, `go-bytes`, `python-bytes`,
`powershell-bytes`, `vba-array`, `vbs-array`, `rust-array`, `javascript-array`, `zig-array`) and
`json`. The key is emitted as a second declaration, not in the summary, and the command prints a
warning because the output is secret material. `--key-symbol` changes the declaration name
(default: `key`).

For password-based encryption, the rendered key is the scrypt output, not the password. Code that
uses that key directly must read the container's salt, nonce, ciphertext, and tag and skip the KDF
step; otherwise use the password with `decrypt`.

Explicit nonces are accepted only for tests and interoperability and trigger a reuse warning.
Every other encryption generates a fresh nonce from the operating system CSPRNG.

## Padding

Padding is explicit. On `encode` it applies only to the fixed-width codecs:

| Single value | Width | List codec  | Chunk |
| ------------ | -----:| ----------- | -----:|
| `ipv4`       | 4     | `ipv4-list` | 4     |
| `ipv6`       | 16    | `ipv6-list` | 16    |
| `mac`        | 6     | `mac-list`  | 6     |
| `uuid`       | 16    | `uuid-list` | 16    |

| `--pad` value | Fill                                                                    |
| ------------- | ----------------------------------------------------------------------- |
| `none`        | Reject a payload that is not already aligned (explicit alignment check) |
| `nop`         | `0x90`                                                                  |
| `zero`        | `0x00`                                                                  |
| `random`      | CSPRNG bytes from `crypto/rand`; default when padding is enabled        |
| `HEX`         | Caller-supplied repeating bytes, for example `CC` or `9090`             |

Rules:

- On `encode`, any other encoding ignores `--pad` with a warning:
  `[!] --pad has no effect for encoding 'base64'; ignoring`.
- **Single-value codecs:** input shorter than the width is filled to exactly that width. Input
  equal to the width is unchanged. Input longer than the width is a hard error even with `--pad`,
  because padding cannot truncate data; the error suggests the matching `-list` codec.
- **List codecs:** only the final partial chunk is filled. A payload that is already a multiple of
  the chunk size is unchanged.
- The target is always the codec width or chunk size. `--pad-to` must match it when used with
  `encode`. On `encrypt`, `decrypt`, `transform`, and `untransform`, padding uses `--pad-to` or
  defaults to 16 bytes (or the codec width when a fixed-width codec is involved).
- Bare `--pad` is shorthand for `--pad random`. `--pad-to` alone also enables random padding.
- Hex patterns repeat cyclically and are truncated to the bytes needed.
- `--pad` is optional. Omitting it keeps the normal behavior: fixed-width codecs reject invalid
  lengths, and no padding is added.
- Padding changes the payload. Reverse operations do not detect or remove it; `encrypt --pad`
  makes `decrypt` return the padded plaintext.

Padding reports the exact chunk count:

```text
[!] input 276 bytes padded by +12 bytes (nop/0x90) → total 288 bytes (18 chunks)
[*] no padding needed (276 bytes, 69 chunks)
[*] no padding needed
```

Oversized single values fail before any padding runs:

```text
[ERROR] ipv6 requires exactly 16 bytes, got 276; --pad cannot truncate data.
        Use --encoding ipv6-list --pad nop to encode as a sequence of 18 addresses.
```

```bash
# 276 -> 288 bytes, filled final chunk, 18 IPv6 addresses
byteforge encode --file calc.bin --encoding ipv6-list --pad nop

# 276 % 4 == 0: no padding needed, 69 IPv4 addresses
byteforge encode --file calc.bin --encoding ipv4-list --pad nop

# Exact single value: no padding needed
byteforge encode --hex c0a80101 --encoding ipv4 --pad nop

# Too large for a single value: hard error with a list-codec suggestion
byteforge encode --file calc.bin --encoding ipv6 --pad nop
```

## Container format

Encrypted output is a self-describing `BFRG` version 1 container:

```text
magic "BFRG" | version | cipher id | kdf id | flags | salt len | nonce len | tag len |
reserved | ciphertext length (uint64 BE) | salt | nonce | ciphertext | tag
```

The fixed header, salt, and nonce are authenticated as associated data. Unknown versions, unknown
algorithms, truncation, trailing data, oversized lengths, and authentication failures are rejected
before any plaintext is written.

`inspect` parses the container strictly and prints only non-secret metadata: cipher, KDF, salt and
nonce lengths, nonce hex, ciphertext length, tag length, and total size. Keys, passwords, and
derived keys are never displayed.

See [`docs/FORMATS.md`](docs/FORMATS.md) for the byte-level container layout and golden vectors.

## Output behavior

- **Payload → stdout or `--output FILE`.** Payload bytes are never mixed with status text.
- **Diagnostics → stderr.** Warnings, progress, verification results, and the summary report all go
  to stderr, so raw binary output is safe to pipe or redirect.
- **No silent overwrite.** Existing files require `--force`.
- **Safe file creation.** New files are created with mode `0600`; forced writes use a temporary
  file and atomic rename where supported.
- **Readable reports.** Textual status output uses ANSI color only when stderr is a terminal and
  `--no-color` is absent.
- **Summary separation.** When the stdout payload does not end with a newline (for example
  `ipv4-list`, `ipv6-list`, raw binary, or a source declaration), the summary is separated by two
  newlines. The payload itself is unchanged.
- **Explicit input only.** Every data operation requires exactly one of `--file` or `--hex`;
  there is no implicit payload or stdin fallback. Stdin is used only for passwords via
  `--password-stdin`.

## Exit codes

| Code | Meaning                                 |
| ----:| --------------------------------------- |
| 0    | Success                                 |
| 1    | General processing failure              |
| 2    | Invalid arguments or unsupported option |
| 3    | Input/output failure                    |
| 4    | Verification or authentication failure  |

If a flag is given without a value, the error names the flag and lists what it accepts. Enum flags
list every registered value, for example:

```text
[ERROR] missing value for --renderer; available renderers: base64, c-array, ...
```

## Security notes

- **Authenticated encryption is the default.** Do not use XOR or RC4 for confidentiality.
- **Entropy is descriptive only.** It is not evidence of safety or correctness.
- **Avoid `--password` on shared systems.** It may be visible in the process list; prefer
  `--password-file` or `--password-stdin`.
- **Key material is secret.** Encryption with a key-capable renderer writes the key beside the
  ciphertext. Treat that output as secret and do not commit or share it.
- **Deleting a key file is not secure erasure.** Backups, storage, and memory may retain copies.
- **A successful decode does not make data trustworthy.** ByteForge verifies integrity and
  round-trip correctness, not intent or provenance.
- **No execution, no loaders.** ByteForge never executes or generates loaders for processed data.
- **Strict parsing.** Container parsing rejects unknown versions, unknown algorithms, truncation,
  trailing data, oversized lengths, and authentication failures.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model and operational guidance.

## Testing

Run the full suite:

```bash
go test ./...
```

Recommended checks before committing or releasing:

```bash
gofmt -l .                 # should print nothing
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

What the suite covers:

- codec round-trips and strict rejection cases, including fixed-width validation;
- golden vectors in [`testdata/`](testdata/README.md);
- container parsing, authentication failures, tampering, and truncation;
- password KDFs, explicit keys, AAD, and compatibility ciphers;
- renderer output shape and the absence of loader constructs;
- padding modes, alignment errors, and encode-specific diagnostics;
- CLI exit codes, flag parsing, output paths, and summary formatting.

Manual smoke test:

```bash
mkdir -p dist
go build -trimpath -o dist/byteforge ./cmd/byteforge

printf 'Hello' > /tmp/hello.bin
dist/byteforge encode --file /tmp/hello.bin --encoding hex --output /tmp/hello.hex
dist/byteforge decode --file /tmp/hello.hex --encoding hex --output /tmp/hello.out
dist/byteforge verify --original /tmp/hello.bin --recovered /tmp/hello.out

printf 'test' > /tmp/plain.bin
printf 'test' | dist/byteforge encrypt --file /tmp/plain.bin --password-stdin --output /tmp/sample.bf
dist/byteforge inspect --file /tmp/sample.bf
printf 'test' | dist/byteforge decrypt --file /tmp/sample.bf --password-stdin --output /tmp/out.bin
dist/byteforge verify --original /tmp/plain.bin --recovered /tmp/out.bin
```

Static build verification on Linux:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/byteforge ./cmd/byteforge
file dist/byteforge
ldd dist/byteforge
```

See [`docs/TESTING.md`](docs/TESTING.md) for the complete strategy, manual cases, and vector
parameters.

## Project layout

```text
byteforge/
├── cmd/byteforge/main.go     process entry point
├── internal/
│   ├── bferrors/             classified errors and exit codes
│   ├── bytesutil/            hexadecimal parsing
│   ├── cli/                  command dispatch, flags, reports
│   ├── codec/                representation codec registry
│   ├── container/            BFRG v1 serializer and strict parser
│   ├── cryptography/         cipher registry, AEAD/compat adapters, KDF
│   ├── fsutil/               non-destructive binary-safe file output
│   ├── input/                file/hex input loading and limits
│   ├── inspect/              hashes, entropy, container metadata
│   ├── padding/              explicit padding modes and diagnostics
│   ├── pipeline/             ordered transformation stages
│   ├── registry/             shared interfaces and metadata
│   ├── renderer/             output renderer registry
│   ├── reporting/            stderr diagnostics and summaries
│   ├── transform/            XOR transform registry
│   └── version/              build identity
├── docs/                     architecture, formats, security, testing
├── testdata/                 golden vectors and container fixtures
├── go.mod
└── README.md
```

## Design decisions and limitations

The following design decisions were resolved for this release:

1. **Language:** Go, compiled native executable.
2. **Interface:** CLI first; no TUI.
3. **Codecs:** the list above, including the typed representations.
4. **Compatibility profiles:** Windows CNG and tiny-AES-C profiles are not implemented. CBC/CTR
   modes are available only as authenticated compatibility modes. No profile claims unverified
   API compatibility.
5. **Container:** encryption output is a self-describing `BFRG` v1 container by default.
6. **Key output:** key-capable data-declaration renderers include the key in the same source file
   on `encrypt`, so the pair is directly usable. Summaries never print keys. `--export-key` is
   opt-in and limited to explicit or generated keys; `raw`, `hex`, and `base64` never carry a key.
7. **Limits:** whole-file processing with a default 64 MiB input limit (`--max-input`). Streaming is
   not implemented.
8. **Targets:** build and test on the development platform first; cross-compile only for verified
   targets listed in CI.
9. **Renderers:** raw, hex, Base64, JSON, and data-only declarations for C, C#, Nim, Go, Python,
   PowerShell, VBA, VBS, Rust, JavaScript, and Zig. No renderer emits a loader or execution code.
10. **Padding:** explicit only, selected with `--pad none|nop|zero|random|HEX`. On `encode` it
    applies only to the eight fixed-width codecs: short single values fill to their exact width,
    list codecs fill only the final partial chunk, and oversized single values fail with a
    list-codec suggestion. Other encodings ignore `--pad` with a warning. `--pad-to` must match
    the codec width on `encode`; non-encode operations default to 16 bytes.

Known limitations:

- Whole-file processing only; there is no streaming mode.
- The default 64 MiB input limit can be raised with `--max-input`, but the entire input is held in
  memory.
- Ciphers and container IDs are fixed at build time; custom algorithms require code changes.
- Cross-compiled binaries must be tested on their target platform before distribution.
- `--password` is inherently less safe than file or stdin input on multi-user systems.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layers, interfaces, data flow
- [`docs/FORMATS.md`](docs/FORMATS.md) — codec grammars, padding rules, and container byte layout
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and operational guidance
- [`docs/TESTING.md`](docs/TESTING.md) — test strategy and how to run it
- [`testdata/README.md`](testdata/README.md) — golden vectors and their parameters
