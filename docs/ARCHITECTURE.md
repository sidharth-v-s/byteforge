# ByteForge Architecture

ByteForge is a single-binary Go CLI. It loads bytes, applies one explicit
operation, optionally transforms the result for display, and writes payload
bytes to stdout or a file. Diagnostics are separate from payload output.

The architecture is deliberately small: no plugin loading, no network access,
no dynamic code execution, and no implicit payload or key.

---

## 1. Layers

```text
                  +-----------------------------+
                  | cmd/byteforge (main)        |
                  +--------------+--------------+
                                 |
                  +--------------v--------------+
                  | internal/cli                |
                  | dispatch, flags, orchestration,
                  | reports, output policy      |
                  +--+-------+-------+-------+--+
                     |       |       |       |
        +------------v+ +----v----+ +v------+ +v-----------+
        | codec       | |crypto-  | |trans- | | inspect /  |
        | registry    | |graphy   | |form   | | verify     |
        +------+------+ +----+----+ +---+---+ +------------+
               |             |          |
               |        +----v-----+    |
               |        |container |    |
               |        +----+-----+    |
               |             |          |
        +------v-------------v----------v------+
        | pipeline (ordered stages, timings)    |
        +------------------+--------------------+
                           |
                  +--------v---------+
                  | renderer registry|
                  +--------+---------+
                           |
                  +--------v---------+
                  | reporting + fsutil|
                  +------------------+
```

Responsibility boundaries:

- **cmd/byteforge** only calls `cli.Run` and exits with its status code.
- **internal/cli** owns argument parsing, validation, key handling, operation
  order, verification, and output. It is the only package that knows about
  multiple layers at once.
- **internal/codec**, **internal/cryptography**, **internal/transform**, and
  **internal/renderer** are independent registries. They do not import the CLI.
- **internal/padding** applies explicit, caller-selected fill to payloads at
  operation boundaries. It never runs unless `--pad` or `--pad-to` is present.
  `encode` additionally restricts padding to fixed-width codecs and reports
  chunk counts; other encodings ignore it with a warning.
- **internal/container** is a pure serializer/parser for the encrypted format.
- **internal/pipeline** runs an explicit stage list and records timings.
- **internal/reporting** writes all human-readable status to stderr.
- **internal/fsutil** performs non-destructive, binary-safe output writes.
- **internal/input** loads file or hex input and enforces size limits.

---

## 2. Packages

| Package | Responsibility |
| --- | --- |
| `cmd/byteforge` | Process entry point; maps `cli.Run` to an exit code |
| `internal/bferrors` | Error classification and exit-code mapping |
| `internal/bytesutil` | Loose but strict hexadecimal parsing |
| `internal/cli` | Command dispatch, flags, usage text, orchestration, reports |
| `internal/codec` | Representation codec registry and implementations |
| `internal/container` | `BFRG` v1 header, serializer, strict parser, AAD construction |
| `internal/cryptography` | Cipher registry, AEAD adapters, compat HMAC construction, KDF |
| `internal/fsutil` | `O_EXCL` writes, atomic forced replacement, existence checks |
| `internal/input` | File/hex loading, 64 MiB default limit, labels |
| `internal/inspect` | SHA-256, Shannon entropy, container metadata |
| `internal/padding` | Explicit payload padding modes, alignment, and fill generation |
| `internal/pipeline` | Ordered byte-stage execution with timings and first-failure stop |
| `internal/registry` | Shared `Info`, `Codec`, `Cipher`, `Renderer`, `Transform`, `Meta` contracts |
| `internal/renderer` | Raw/hex/Base64/C/Python/JSON renderers |
| `internal/reporting` | Banner, status lines, warnings, previews, summaries, TTY detection |
| `internal/transform` | XOR single-byte and repeating-key transforms |
| `internal/version` | Build version and verbose build identity |

Dependencies flow downward only. Registries never import the CLI, and the
container package never imports the CLI or renderer. `go.mod` has one direct
dependency, `golang.org/x/crypto`, used for scrypt and ChaCha20-Poly1305.

---

## 3. Interfaces

The shared contracts live in `internal/registry` and intentionally avoid a
one-size-fits-all cipher signature.

```go
type Codec interface {
    Info() Info
    Encode(data []byte) ([]byte, error)
    Decode(data []byte) ([]byte, error)
}

type Cipher interface {
    Info() Info
    KeySize() int
    NonceSize() int
    TagSize() int
    CiphertextLen(plaintextLen int) int
    Encrypt(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)
    Decrypt(key, nonce, ciphertext, tag, aad []byte) (plaintext []byte, err error)
}

type Renderer interface {
    Info() Info
    Render(data []byte, meta Meta) ([]byte, error)
}

type Transform interface {
    Info() Info
    ValidateKey(key []byte) error
    Apply(data, key []byte) ([]byte, error)
}
```

Design consequences:

- `CiphertextLen` lets the CLI build and authenticate the container header
  before encrypting. An incorrect length is caught by `Header.Encode`.
- Tags are returned separately so the container can store them after the
  ciphertext and so tag length is explicit in the header.
- `Decrypt` must verify authentication before returning plaintext. There is no
  "decrypt anyway" mode.
- Renderers receive only transformed bytes and non-secret `Meta`. They cannot
  access keys, passwords, or the original path unless the CLI puts it in
  metadata (it does not put secrets there).
- Encryption with a key-capable renderer is the one explicit exception: the CLI
  calls `renderer.RenderWithKey` with the key bytes so they can be formatted as
  a second data declaration. The key is still never placed in `Meta`, never
  appears in a summary, and the command warns that the output is secret.
- Transforms expose the same `Apply` for both directions because XOR is
  symmetric.

Registry registration happens in package `init` functions. Duplicate names or
IDs panic at startup, which turns a programming error into an immediate build
or test failure rather than ambiguous runtime selection.

---

## 4. Operation flows

### 4.1 `encode`

```text
validate flags -> validate codec + renderer + padding + output path
  -> load input (--file or --hex)
  -> explicit padding (fixed-width codecs only):
       single value -> fill short input to exact width; reject oversized input
       list codec   -> fill only the final partial chunk
       other codec  -> ignore --pad with a warning
  -> pipeline: codec.Encode
  -> round-trip check: codec.Decode(encoded) == padded input
  -> renderer.Render(encoded, meta)
  -> write stdout or file
  -> summary to stderr
```

### 4.2 `decode`

```text
validate -> load input -> pipeline: codec.Decode
  -> explicit padding: --pad/--pad-to (single-value exact width, sequence
     element width, or 16; oversized single values fail before padding)
  -> verification: decode(encode(decoded)) == decoded
  -> render -> write -> summary
```

The decode verification deliberately re-encodes and re-decodes rather than
comparing text, because many inputs have multiple valid textual spellings.

### 4.3 `encrypt`

```text
validate cipher (legacy gate) -> validate renderer/output/export path
  -> load plaintext
  -> explicit padding: --pad/--pad-to (default multiple: 16)
  -> choose key source:
       password -> fresh 16-byte salt -> scrypt -> cipher-sized key
       explicit key -> exact key-size check
       none -> random key; key-capable renderers include it, otherwise --export-key
  -> nonce: explicit (test/interop, warned) or fresh CSPRNG bytes
  -> build header with ciphertext length and tag size
  -> AAD = fixed header || salt || nonce || --aad
  -> cipher.Encrypt
  -> header.Encode(ciphertext, tag)
  -> optional internal decrypt + plaintext comparison
  -> optional key export (never for passwords)
  -> key-capable renderer: renderer.RenderWithKey(container, key)
     otherwise: renderer.Render(container)
  -> write stdout or file
  -> summary to stderr
```

### 4.4 `decrypt`

```text
validate -> load container -> strict container.Parse(bounded by --max-input)
  -> resolve cipher by ID, gate legacy algorithms
  -> select key source from stored KDF ID:
       none -> explicit key only
       scrypt -> password only, derive with stored salt
  -> AAD = parsed prefix || --aad
  -> cipher.Decrypt (authentication first)
  -> optional re-encrypt and compare ciphertext/tag
  -> explicit padding after decryption (--pad/--pad-to)
  -> render plaintext -> write -> summary
```

No plaintext is rendered or written until `Decrypt` succeeds. The optional
re-encryption check catches adapters that decrypt inconsistently.

### 4.5 `transform` / `untransform`

The two commands are aliases for the same operation. The selected transform is
applied, then applied again to verify that the original bytes are restored.
The transform and key are explicit; there is no default key.

Explicit padding is applied to the payload before `transform` and after
`untransform`. Verification compares against the padded payload, because
padding is part of the input to the transform stage.

### 4.6 `inspect`

`inspect` computes size, SHA-256, and Shannon entropy. If the input starts with
`BFRG`, it strictly parses the container. A malformed container is an error,
not a reason to fall back to generic inspection. Text and JSON output are
available; both are payload output written through the normal output path.

### 4.7 `verify`

Two modes:

- `--original FILE --recovered FILE`: byte-for-byte comparison.
- `--file FILE --sha256 HEX`: hash comparison, case-insensitive expected digest.

Both modes print a report and return exit 4 when the check fails. The report is
written to stdout or `--output`; the failure line is additionally reported to
stderr through the normal error path.

### 4.8 `formats`

Lists codecs, transforms, modern ciphers, compatibility ciphers, legacy
ciphers, and renderers as separate groups. `--json` emits the same information
plus `Info` metadata for automation. Encryption is never presented as an
encoding, and XOR/RC4 are never presented as recommended protection.

---

## 5. Input and output

### Input

- Exactly one of `--file FILE` or `--hex HEX` is required. Missing input is a
  usage error; there is no built-in sample payload.
- Reads are binary-safe. Nothing is decoded as text implicitly.
- The default limit is 64 MiB (`64 << 20`) per input file. `--max-input`
  raises or lowers it. Files are checked by `Stat` before reading and again
  after a bounded read.
- Hex strings go through the same loose parser as the `hex` codec and are
  subject to the same byte limit.
- Password and key files are read with a separate 1 MiB limit.

### Output

- Payload goes to stdout when `--output` is absent.
- Diagnostics, warnings, previews, and summaries always go to stderr.
- Raw binary output to a terminal triggers a warning; it is never mixed with
  status text.
- Existing files are never overwritten without `--force`. The check happens
  before expensive work where possible, and the final create uses `O_EXCL`, so
  a concurrent creator also loses cleanly.
- New files are created with mode `0600`. Forced writes use a temporary file in
  the destination directory, `fsync`, and an atomic rename. On Windows, where
  rename-over-existing may fail, the destination is removed and the rename is
  retried once.
- A failed write removes its partial destination.

### Output modes

| Renderer | Payload type | Notes |
| --- | --- | --- |
| `raw` | Binary | No added newline; default |
| `hex` | ASCII | One trailing LF; empty input stays empty |
| `base64` | ASCII | One trailing LF; empty input stays empty |
| `c-array` | C source | Data declaration only |
| `csharp-array` | C# source | Data declaration only |
| `nim-array` | Nim source | Data declaration only |
| `go-bytes` | Go source | Data declaration only |
| `python-bytes` | Python source | Data literal only |
| `powershell-bytes` | PowerShell source | Data declaration only |
| `vba-array` | VBA source | Data declaration only |
| `vbs-array` | VBScript source | Data declaration only |
| `rust-array` | Rust source | Data declaration only |
| `javascript-array` | JavaScript source | Data declaration only |
| `zig-array` | Zig source | Data declaration only |
| `json` | JSON | Schema 1.0, Base64 `data` |

---

## 6. Error model

Every user-facing failure is a `bferrors.Error` with one of four kinds. The
CLI prints the message to stderr and returns the mapped exit code.

| Kind | Exit | Typical causes |
| --- | ---: | --- |
| `Processing` | 1 | malformed codec data, structural container error, pipeline failure |
| `Usage` | 2 | missing input, unknown format, conflicting flags, unsupported version/cipher/KDF, legacy cipher without opt-in |
| `IO` | 3 | missing/unreadable input, oversized file, existing output, write failure |
| `Verification` | 4 | authentication failure, failed round trip, failed hash/byte comparison |

`bferrors.KindOf` defaults unclassified errors to `Processing`, so an
unexpected internal error can never masquerade as success. `errHelp` is the one
sentinel that returns 0 after printing help.

Authentication failures are wrapped as `Verification` at the CLI boundary even
if an adapter returns a lower-level error. This keeps exit code 4 stable.

---

## 7. Limits and performance

- Whole-file processing. No streaming API is implemented in 0.1.0.
- Default maximum input: 64 MiB. This bounds memory use for input, output,
  containers, and Base64/hex expansions.
- Encryption holds plaintext, ciphertext, tag, container, and rendered output
  in memory. For the default limit this is acceptable for a CLI tool but not
  intended for very large files.
- scrypt at N=2^15, r=8, p=1 uses roughly 32 MiB per derivation.
- Registries are read-mostly and guarded by `sync.RWMutex`; registration
  happens during `init`, before concurrent use.
- Go's standard library provides constant-time comparison for HMAC
  (`hmac.Equal`) and authenticated decryption for AEAD ciphers.

---

## 8. Extending ByteForge

### Adding a representation codec

1. Implement `registry.Codec` in `internal/codec`.
2. Give it a unique lowercase `Info().Name`, a description, and
   `SecurityRepresentation`.
3. Register it in an `init` function.
4. Define exact grammar: alphabet, padding, whitespace, case, length rules, and
   error behavior.
5. Add round-trip tests, invalid-input tests, a vector in
   `testdata/codecs.json`, and documentation in `docs/FORMATS.md`.
6. For typed codecs, reject all unexpected lengths instead of guessing.

### Adding a cipher

1. Implement `registry.Cipher` in `internal/cryptography`.
2. Assign a new stable container ID and register it exactly once.
3. Validate key and nonce sizes in both directions.
4. Return the exact ciphertext length from `CiphertextLen` before encryption.
5. If the mode is not an AEAD, add an authenticated construction and verify it
   before decrypting. Do not expose a bare unauthenticated mode.
6. Classify it as authenticated, compatibility, or legacy. Legacy ciphers must
   require `--allow-legacy`.
7. Add round-trip, tamper, wrong-key, wrong-nonce, wrong-AAD, and vector tests.

### Adding a renderer

1. Implement `registry.Renderer` in `internal/renderer`.
2. Use only `data` and `registry.Meta`; never access keys or the filesystem.
3. Define the exact output grammar, including trailing newline behavior and
   empty-input behavior.
4. Data-only outputs must not contain loader or execution code.
5. Add syntax tests, empty-input tests, symbol/width validation tests, and
   documentation.

### Adding a transform

1. Implement `registry.Transform` in `internal/transform`.
2. Validate key length in `ValidateKey` and again in `Apply`.
3. Mark it `SecurityTransform` and include a warning that it is not
   encryption.
4. Document that `transform` and `untransform` are the same operation only if
   the transform is an involution; otherwise add a distinct inverse path.

Any change to the container header, AAD construction, cipher IDs, KDF IDs, or
fixed KDF parameters is a format change. It requires a new container version
and new vectors; it cannot be slipped into version 1.

---

## 9. Release decisions and known limitations

- Go 1.25, compiled native executable. No Python runtime is required.
- CLI only; no TUI.
- Data-only renderers cover C, C#, Nim, Go, Python, PowerShell, VBA, VBS, Rust,
  JavaScript, Zig, raw bytes, hex, Base64, and JSON. None emit a loader.
- Default cipher is AES-256-GCM. ChaCha20-Poly1305 and AES-128-GCM are
  available for interoperability.
- CBC and CTR are compatibility modes with an added HMAC-SHA256 construction.
  They are not bare CBC/CTR and do not interoperate with tools that expect
  unauthenticated CBC/CTR.
- RC4 is implemented only through the Go standard library, is disabled by
  default, and is not recommended.
- Windows CNG and tiny-AES-C compatibility profiles are not implemented. There
  is no claim of compatibility with those APIs.
- UUID mixed-endian (Windows GUID) mode is not implemented.
- No streaming, compression, or password-strength estimator.
- No secure-erasure guarantee. Go's garbage collector and the operating
  system may retain copies of keys, passwords, and plaintext.
- No network functionality, telemetry, plugin loading, or payload execution.

See [SECURITY.md](SECURITY.md) for the threat model and [FORMATS.md](FORMATS.md)
for the on-disk specification.
