# ByteForge Testing

ByteForge is tested at the package level and through end-to-end CLI tests. The
suite emphasizes deterministic vectors, round-trip properties, strict rejection
of malformed input, authentication-before-plaintext behavior, output purity,
and stable exit codes.

---

## 1. Running the suite

```bash
go test ./...
```

Useful variants:

```bash
# Race detector (recommended before a release)
go test -race ./...

# Verbose package/test names
go test -v ./...

# Coverage summary
go test -cover ./...

# Coverage profile
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Formatting and static checks
gofmt -l .
go vet ./...

# Release build
go build -trimpath -o dist/byteforge ./cmd/byteforge

# Verify the binary
./dist/byteforge version --verbose
```

The project targets Go 1.25 or newer. Tests use only temporary directories and
do not require network access after modules are downloaded.

---

## 2. Test layout

| Area | Files | What is exercised |
| --- | --- | --- |
| Codecs | `internal/codec/codec_test.go`, `internal/codec/typed_list_test.go`, `internal/codec/vectors_test.go` | Round trips, all 256 byte values, empty/small/large inputs, known outputs, typed lengths, typed sequences, invalid syntax, separators, UUID variants, published vectors |
| Cryptography | `internal/cryptography/crypto_test.go`, `internal/cryptography/vectors_test.go` | Every cipher round trip across boundary lengths, wrong key/nonce/AAD/tag/ciphertext, parameter validation, NIST AES-GCM tags, CBC MAC-before-decrypt, stable IDs, KDF, RNG, golden containers |
| Container | `internal/container/container_test.go` | Serialization, AAD layout, length validation, bad magic/version, flags/reserved, truncation, trailing data, oversized lengths, field bounds |
| Renderers | `internal/renderer/render_test.go`, `internal/renderer/languages_test.go`, `internal/renderer/key_test.go` | Raw identity, hex/Base64 framing, C array syntax/symbol/width/empty behavior, C#/Nim/Go/PowerShell/VBA/VBS/Rust/JavaScript/Zig declarations, Python literal/identifier/empty behavior, JSON schema/data round trip, key declarations and JSON key object, no ANSI in payload, no loader constructs |
| Transforms | `internal/transform/transform_test.go` | Known XOR vectors, involution, key bounds, empty input, metadata warnings |
| Filesystem | `internal/fsutil/write_test.go` | Mode `0600`, no silent overwrite, forced replacement without temp leftovers, missing directory handling |
| Input | `internal/input/input_test.go` | Missing/conflicting input, loose hex parsing, empty file preservation, missing file/directory, size limits |
| Pipeline | Exercised through CLI | Ordered stages, first-failure stop, timings |
| CLI | `internal/cli/cli_test.go` | Encode/decode round trip, no implicit input, overwrite protection, exit codes, password encrypt/decrypt, wrong password, tamper, generated key export, stdout purity, RC4 gate, inspect JSON, verify mismatch, formats groups, aliases, transform round trip |

The `inspect` package is covered through CLI integration (`inspect --json` on a
real container). The reporting package is covered indirectly through assertions
on stderr contents, banner suppression, and verification lines.

---

## 3. Golden vectors

Published vectors live in `testdata/`:

```text
testdata/
├── codecs.json                 codec input/output vectors
├── plaintext/ByteForge.bin     the 9-byte plaintext "ByteForge"
└── containers/
    ├── gcm-key.bf / .hex
    ├── gcm128-key.bf / .hex
    ├── chacha-key.bf / .hex
    ├── cbc-key.bf / .hex
    ├── gcm-key-aad.bf / .hex
    └── gcm-password.bf / .hex
```

`internal/cryptography/vectors_test.go` verifies each container's:

- binary bytes match its `.hex` companion;
- SHA-256 matches the published digest;
- header parses and selects the expected cipher;
- KDF ID and salt handling are correct;
- decryption recovers exactly `ByteForge`;
- a one-bit change in the tag is rejected.

It also pins the derived key for the fixed-salt password vector. The password
vector's salt is intentionally fixed for reproducibility; normal encryption
uses a fresh random salt.

`internal/codec/vectors_test.go` verifies every entry in `codecs.json` in both
directions. Raw byte outputs are stored as `encodedHex`; `encoded` is present
only when the encoded bytes are valid UTF-8, so binary data cannot be corrupted
by JSON string escaping.

**If you change a vector, you must update the test expectations and
`docs/FORMATS.md`.** A failing vector test is a format change, not a test to
delete.

---

## 4. Properties under test

### Representation codecs

For every reversible codec and every payload:

```text
decode(encode(payload)) == payload
```

Covered payloads include empty input where the CLI allows it, one byte, all 256
byte values, embedded nulls, high bytes, and text. Fixed-length codecs are
tested only with their exact widths; every other width must be rejected.

For the sequence codecs (`mac-list`, `ipv4-list`, `ipv6-list`, `uuid-list`):

```text
decode(encode(payload)) == payload     for every multiple of the element width
len(encode(payload))                   is a multiple of the element width
```

Additional properties:

- a non-multiple input length is rejected with a usage error and no output;
- encode emits exactly `n-1` LF separators for `n` values and no trailing LF;
- decode accepts LF, CRLF, spaces, tabs, commas, and semicolons as separators;
- empty and blank-only input decode to empty bytes;
- a malformed field anywhere in the sequence fails the whole decode and names
  the 1-based field number;
- the single-value codec's oversize error suggests the matching `-list` codec.

The CLI test `TestTypedListSequence` exercises the reported 276-byte case as 69
IPv4 values end to end, including `verify`-style byte equality.

### Ciphers

For every registered cipher and every boundary length (0, 1, 15, 16, 17, and
1024 bytes):

```text
decrypt(encrypt(plaintext)) == plaintext
```

and each of these must fail with a verification error and return no plaintext:

- modified ciphertext;
- modified tag;
- modified nonce;
- modified AAD;
- wrong key.

CBC additionally proves that authentication is checked before padding: a
modified final block is rejected even if it might decrypt to valid padding.

### Container parsing

For a structurally valid container, the parser must accept it and reproduce the
exact header, salt, nonce, ciphertext, and tag. Mutating magic, version, flags,
reserved byte, lengths, or truncating/trailing bytes must fail. The parser must
never allocate based on an unbounded file-controlled length.

### Transform involution

```text
apply(apply(data, key), key) == data
```

for both XOR variants. XOR is tested as a transform, not as confidentiality.

### Language renderers

Every data-declaration renderer is checked for:

- the expected declaration form and byte literals for a fixed sample;
- a valid empty declaration when input is empty;
- symbol validation, including PowerShell's optional leading `$`;
- `--bytes-per-line` grouping and the 1–256 bounds;
- absence of loader constructs such as `malloc`, `VirtualAlloc`, `CreateThread`,
  `LoadLibrary`, `system(`, `exec(`, or `import os`;
- no ANSI escape sequences in payload output.

For encryption with a key-capable renderer, the suite checks that every
key-capable renderer emits the data and key declarations automatically, that the
rendered key bytes match the key used, that the key header omits a digest, that
JSON adds a Base64 key object, that `raw`/`hex`/`base64` omit the key, and that
symbol conflicts are rejected.

The suite validates text shape and data-only behavior. It does not compile every
language; language-level syntax errors must be caught by review and, where a
toolchain is available, by compiling generated samples.

### Explicit padding

`internal/padding` is tested in isolation and through the CLI:

```text
apply(apply-aligned payload, mode) == payload       for every mode
len(padded) % multiple == 0                         when padding is enabled
padded[:len(original)] == original                  always
```

- `none` accepts aligned input unchanged and rejects misalignment with a usage
  error that names the multiple and the available fill modes.
- `nop`, `zero`, `CC`, and repeating patterns produce the exact expected bytes;
  `9090` repeats and truncates correctly.
- `random` adds exactly the requested number of bytes and preserves the prefix.
- On `encode`, padding is applied only to the eight fixed-width codecs. Other
  encodings are unchanged and emit
  `[!] --pad has no effect for encoding '<name>'; ignoring`.
- List codecs fill only the final partial chunk and report the exact total and
  chunk count:
  `[!] input 276 bytes padded by +12 bytes (nop/0x90) → total 288 bytes (18 chunks)`.
- An aligned list payload reports `[*] no padding needed (N bytes, K chunks)`.
- Single-value codecs (`mac`, `ipv4`, `ipv6`, `uuid`) fill short input up to
  their exact width and report `[*] no padding needed` when already exact.
- Oversized single-value input is rejected before padding with
  `--pad cannot truncate data.` and a list-codec suggestion that preserves the
  selected pad mode.
- `--pad-to` must match the codec width on `encode`; an incompatible value is
  rejected.
- `--pad` without a value behaves like `--pad random`; `--pad-to` alone also
  enables random padding.
- Invalid `--pad` values list every mode; invalid `--pad-to` values repeat the
  1–1048576 range.
- Padded decode and padded encrypt/decrypt round trips return the padded
  payload, not the original length.

### CLI contracts

- Missing input exits 2 and never processes a built-in sample.
- Unknown codec/cipher/renderer exits 2.
- A flag without a value exits 2 and names the flag plus its accepted values:
  enum flags list every registered value, other flags describe the expected form.
- An invalid integer value exits 2 and repeats the accepted range.
- Encryption with a key-capable renderer embeds the key automatically, warns on
  stderr, and never prints the key in the summary. A random key may be generated
  without `--export-key` because the key-capable output carries it. `raw`,
  `hex`, and `base64` never include a key, so a generated key with those
  renderers still requires `--export-key`.
- Missing file, missing output directory, and existing output exit 3.
- Wrong password, tampered container, failed comparison, and failed hash exit 4.
- Raw payload on stdout is byte-identical to the requested output and contains
  no status text.
- Reports and summaries are on stderr.
- Passwords never appear in stderr.
- A failed authentication writes no plaintext file.
- `--force` overwrites; without it, the original file is untouched.
- Legacy RC4 requires `--allow-legacy` for both encryption and decryption.
- Padding is only applied when `--pad` or `--pad-to` is present; `--pad none`
  rejects misalignment and omitting padding flags preserves prior behavior.
- On `encode`, `--pad` is limited to fixed-width codecs; other encodings warn
  and ignore it. `--pad-to` must match the codec width on `encode`.
- `formats` keeps codecs, transforms, modern ciphers, compatibility ciphers,
  legacy ciphers, and renderers in separate groups, and lists padding modes.

---

## 5. Manual smoke test

The automated suite is authoritative, but a short manual pass catches
integration issues with real terminals and files:

```bash
BIN=./dist/byteforge
TMP=$(mktemp -d)
printf 'ByteForge\x00\x01\xff' > "$TMP/input.bin"

# Codec round trip
"$BIN" encode --file "$TMP/input.bin" --encoding base64 -o "$TMP/payload.txt" --no-banner
"$BIN" decode --file "$TMP/payload.txt" --encoding base64 -o "$TMP/recovered.bin" --no-banner
"$BIN" verify --original "$TMP/input.bin" --recovered "$TMP/recovered.bin" --no-banner

# Password encryption without putting the password in argv
printf 'correct horse battery staple\n' | \
  "$BIN" encrypt --file "$TMP/input.bin" --password-stdin -o "$TMP/sample.bf" --no-banner
printf 'correct horse battery staple\n' | \
  "$BIN" decrypt --file "$TMP/sample.bf" --password-stdin -o "$TMP/plain.bin" --no-banner
"$BIN" inspect --file "$TMP/sample.bf" --no-banner

# Renderers
"$BIN" encode --file "$TMP/input.bin" --encoding hex --renderer c-array --symbol payload -o "$TMP/payload.c" --no-banner
"$BIN" encode --file "$TMP/input.bin" --encoding base64 --renderer python-bytes -o "$TMP/payload.py" --no-banner
"$BIN" encode --file "$TMP/input.bin" --encoding hex --renderer rust-array --symbol PAYLOAD -o "$TMP/payload.rs" --no-banner
"$BIN" encode --file "$TMP/input.bin" --encoding hex --renderer powershell-bytes -o "$TMP/payload.ps1" --no-banner
"$BIN" encode --file "$TMP/input.bin" --encoding hex --renderer json -o "$TMP/payload.json" --no-banner

# Key embedded beside the ciphertext automatically (the output is secret)
printf 'correct horse battery staple\n' | \
  "$BIN" encrypt --file "$TMP/input.bin" --password-stdin \
    --renderer javascript-array -o "$TMP/payload.js" --no-banner

# Explicit padding: single value, list chunk, no-op, and hard error
printf '\x00\x01\x02\x03\x04\x05\x06' > "$TMP/mac7.bin"
"$BIN" encode --file "$TMP/mac7.bin" --encoding mac-list --pad zero -o "$TMP/mac.txt" --no-banner
printf '\x20\x01\x0d\xb8' > "$TMP/v6short.bin"
"$BIN" encode --file "$TMP/v6short.bin" --encoding ipv6 --pad zero -o "$TMP/v6.txt" --no-banner
"$BIN" encode --file "$TMP/mac7.bin" --encoding ipv6-list --pad nop -o "$TMP/v6list.txt" --no-banner
"$BIN" encode --file "$TMP/mac7.bin" --encoding ipv6-list --pad -o "$TMP/v6rand.txt" --no-banner
"$BIN" encode --file "$TMP/mac7.bin" --encoding ipv4-list --pad none -o "$TMP/none.txt" --no-banner
echo "pad-none exit: $?"           # 2 when input is misaligned
head -c 276 /dev/zero > "$TMP/large.bin"
"$BIN" encode --file "$TMP/large.bin" --encoding ipv6 --pad nop -o "$TMP/bad.txt" --no-banner
echo "ipv6-oversize exit: $?"      # 2; suggests ipv6-list --pad nop
"$BIN" encode --file "$TMP/mac7.bin" --encoding base64 --pad nop -o "$TMP/base64.txt" --no-banner
echo "non-fixed pad warning shown above; exit: $?"   # 0

# Padded encryption returns the padded plaintext on decrypt
printf 'correct horse battery staple\n' | \
  "$BIN" encrypt --file "$TMP/input.bin" --password-stdin --pad zero --pad-to 16 \
    -o "$TMP/padded.bf" --no-banner
printf 'correct horse battery staple\n' | \
  "$BIN" decrypt --file "$TMP/padded.bf" --password-stdin -o "$TMP/padded-plain.bin" --no-banner

# Expected failures
printf 'wrong password\n' | "$BIN" decrypt --file "$TMP/sample.bf" --password-stdin -o "$TMP/nope.bin" --no-banner
echo "wrong-password exit: $?"     # 4
"$BIN" encrypt --file "$TMP/input.bin" --cipher rc4 --key "$(printf '11%.0s' {1..32})" -o "$TMP/rc4.bf" --no-banner
echo "rc4 exit: $?"                # 2
"$BIN" encode --encoding hex --no-banner
echo "missing-input exit: $?"      # 2

rm -rf "$TMP"
```

Additional checks worth doing before a release:

- `./dist/byteforge version --verbose`
- `./dist/byteforge formats` and `formats --json`
- `--pad` variants appear in `formats` and in every operation's `--help`
- raw binary output to a terminal shows a warning (and is not mixed with logs)
- `--no-color` and `--no-banner` behave as documented
- `--force` replaces an existing file atomically and leaves no temp files
- `inspect` rejects a container with a bad magic after `BFRG`
- a container produced on one platform decrypts on another

---

## 6. Coverage gaps and known limitations

The current suite does not cover:

- fuzzing of codec and container parsers (`go test -fuzz` targets are not yet
  defined);
- Windows/macOS CI, path-permission differences, or the Windows rename-retry
  branch;
- external interoperability of the CBC/CTR HMAC construction with other tools
  (it is a ByteForge-specific construction);
- timing or side-channel analysis beyond using constant-time primitives;
- inputs near or above the 64 MiB default limit under memory pressure;
- malicious `--output`/`--key-file` path races beyond `O_EXCL` and atomic
  rename;
- terminal escape injection in verbose previews (payload bytes are rendered as
  hex and printable ASCII only);
- a TUI, which is not implemented.

Contributions should add a focused test with every behavior change. For parser
changes, add both an acceptance vector and a rejection case. For cryptographic
changes, add a known-answer vector and a tamper case.

---

## 7. Adding tests

Guidelines:

1. Prefer table-driven tests with explicit input and expected bytes.
2. Test failure classes (`bferrors.KindOf`) and exit codes, not just error
   strings.
3. Assert that failed authentication returns no plaintext and writes no file.
4. Keep secrets and payloads synthetic; never commit real keys or user data.
5. For renderers, assert exact framing (newlines, empty-input behavior) and the
   absence of executable constructs.
6. For new golden vectors, update `testdata/`, the test table, and
   `docs/FORMATS.md` together.
7. Run `gofmt -l .`, `go vet ./...`, `go test ./...`, and ideally
   `go test -race ./...` before submitting.

A change that makes a security property untestable should be treated as a
design regression, not merely a coverage gap.
