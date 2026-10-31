# ByteForge Formats

This document is the byte-level reference for ByteForge 0.1.0. It covers
representation codecs, reversible transforms, cipher constructions, the
`BFRG` v1 encrypted container, KDF parameters, renderers, explicit payload
padding, and the published golden vectors. The normative test vectors live in
[`testdata/`](../testdata/).

ByteForge keeps three concepts separate:

1. **Representation codecs** change how bytes are written as text or typed
   values. They provide no confidentiality.
2. **Ciphers** transform bytes using key material. Modern ciphers are
   authenticated; XOR transforms are explicitly not encryption.
3. **Renderers** format the final byte stream for output. They are independent
   of the codec or cipher that produced it.

Explicit payload padding (§9) is an optional, caller-requested stage outside
all three. It is never applied implicitly.

All format identifiers are lowercase ASCII. Identifiers and container IDs are
stable for a released major version and must not be reused or renumbered.

---

## 1. Representation codecs

Codecs are reversible byte-to-byte conversions. Text codecs emit ASCII and
return it as bytes; `raw` is the identity. `encode` applies a codec, while
`decode` reverses it. The CLI verifies round trips by default (`--no-verify`
skips the check).

### 1.1 Variable-length codecs

| Identifier       | Encoded form                                             | Decoder input policy                                                                                                      |
| ---------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `hex`            | Uppercase hex, two digits per byte                       | Ignores spaces, tabs, CR, LF, `:`, `-`, `,`, `_`, and `0x`/`0X`/`\x`/`\X` prefixes; requires an even number of hex digits |
| `base64`         | RFC 4648 §4 standard alphabet, `=` padding               | Ignores ASCII whitespace; padding required; strict trailing bits                                                          |
| `base64url`      | RFC 4648 §5 URL-safe alphabet (`-`, `_`), `=` padding    | Ignores ASCII whitespace; padding required; strict trailing bits                                                          |
| `base32`         | RFC 4648 §6 uppercase alphabet, `=` padding              | Ignores ASCII whitespace; case-insensitive                                                                                |
| `ascii85`        | Go `encoding/ascii85` encoding                           | Ignores ASCII whitespace; no Adobe `<~`/`~>` framing                                                                      |
| `raw`            | Unchanged bytes                                          | Identity                                                                                                                  |
| `decimal`        | Values `0`–`255` joined by one space                     | Whitespace, comma, or semicolon separators; unsigned values only                                                          |
| `octal`          | Three-digit octal groups `000`–`377` joined by one space | Same separators; optional `0o`/`0O` or `\` prefix; 1–3 digits                                                             |
| `binary`         | Eight-bit groups joined by one space                     | Same separators; optional `0b`/`0B` per group; one long run whose length is a multiple of 8 is split into bytes           |
| `c-escaped`      | Quoted C string with every byte as `\xhh`                | Requires surrounding quotes; supports `\xHH`, 1–3 digit octal, and common single-character escapes                        |
| `unicode-escape` | `\u00HH` per byte, lowercase hex                         | Whitespace between escapes; only the `\u00HH` form is accepted                                                            |

Notes:

- `hex` encodes empty input to empty text and decodes empty text to empty bytes
  at the package level. The CLI still rejects an omitted or empty `--hex`
  argument as missing input.
- Base64 and Base64URL decoding is strict: non-canonical trailing bits and
  missing padding are rejected.
- Base32 uses standard padding; lowercase input is accepted on decode and
  normalized internally.
- ASCII85 output is not wrapped and contains no Adobe delimiters. The decoder
  accepts `z` for a zero group as defined by Go's standard implementation.
- `unicode-escape` maps each byte `b` to code point U+00`b` (`Latin-1`). This is
  a byte-preserving escape form, not UTF-8 text encoding; `0x80`–`0xFF` do not
  become multi-byte UTF-8 sequences.
- `c-escaped` output never appends an implicit NUL terminator. A trailing
  `\x00` appears only when the input actually contains a zero byte.
- `ascii85` decoding allocates four bytes of headroom because Go's decoder
  writes whole internal groups even for a partial final block.

### 1.2 Fixed-length typed codecs

These codecs represent a single typed value. They reject every other input
length rather than guessing intent.

| Identifier | Required input | Encoded form                                                     |
| ---------- | --------------:| ---------------------------------------------------------------- |
| `mac`      | 6 bytes        | `AA:BB:CC:DD:EE:FF` (uppercase)                                  |
| `ipv4`     | 4 bytes        | Dotted quad, for example `192.168.1.10`                          |
| `ipv6`     | 16 bytes       | Canonical text from `net.IP.String()`, for example `2001:db8::1` |
| `uuid`     | 16 bytes       | Lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`                 |

Decoding rules:

- `mac` trims surrounding whitespace, ignores `:`, `-`, `.`, spaces, and tabs,
  then parses hex. Exactly six octets are required. Other hex separators such
  as `,`, `_`, or `0x` are accepted through the shared hex parser.
- `ipv4` accepts a dotted quad only. IPv6 text (including `::ffff:...`) is
  rejected. The result is exactly four bytes.
- `ipv6` accepts IPv6 text only; IPv4 text is rejected. The result is exactly
  sixteen bytes in network order.
- `uuid` accepts the canonical 36-character hyphenated form only. Braces,
  URNs, compact 32-character forms, and other variants are rejected. Bytes are
  interpreted in RFC 4122/network order; there is no Windows GUID
  mixed-endian mode. A UUID-shaped value is not validated as a real,
  generated UUID unless a caller checks version/variant bits separately.

MAC and IP renderings are data formatting only. They do not imply that the
input identifies a real device or endpoint.

### 1.3 Typed sequence codecs (`-list`)

Fixed-width codecs represent exactly one value, so they cannot represent longer
data without padding. The codecs never pad implicitly: invented padding would
alter the data and could not be removed unambiguously on decode. Instead, each
fixed-width type has a lossless sequence codec. A caller that intentionally
wants alignment can request the explicit `--pad` payload stage (§9) before
encoding; that is a visible data change, not part of the codec.

| Identifier  | Element width | Encode                    | Decode                                     |
| ----------- | -------------:| ------------------------- | ------------------------------------------ |
| `mac-list`  | 6 bytes       | One MAC per line          | Whitespace, comma, or semicolon separators |
| `ipv4-list` | 4 bytes       | One dotted quad per line  | Same separators                            |
| `ipv6-list` | 16 bytes      | One IPv6 address per line | Same separators                            |
| `uuid-list` | 16 bytes      | One UUID per line         | Same separators                            |

Rules:

- Input length must be an exact multiple of the element width. Any remainder is
  a usage error naming the required width and the observed remainder; the codec
  never pads, truncates, or drops bytes.
- Encode emits values in input order separated by a single `\n` and appends no
  trailing newline. Empty input encodes to empty output.
- Decode splits on Unicode whitespace, `,`, or `;`, so blank lines, trailing
  newlines, spaces, and comma-separated values are all accepted. Empty or
  blank-only input decodes to empty bytes.
- Each field is decoded by the single-value codec, so the element grammar is
  exactly that of `mac`, `ipv4`, `ipv6`, or `uuid`. A malformed field fails the
  whole decode and reports the 1-based field number.
- Round trips are byte-exact. A 276-byte file, for example, is 69 IPv4 values:

```bash
byteforge encode --file calc.bin --encoding ipv4-list --output addresses.txt
byteforge decode --file addresses.txt --encoding ipv4-list --output recovered.bin
```

When a single-value codec receives more data than its width, the error suggests
the matching `-list` identifier (for example `use --encoding ipv4-list for a
sequence`). It does not switch automatically, because a silent fallback would
hide the user's intent.

---

## 2. Reversible transforms

XOR transforms are grouped separately from ciphers because they provide
obfuscation, not confidentiality. `transform` and `untransform` are the same
operation because XOR is an involution.

| Identifier          | Key            | Operation                                |
| ------------------- | -------------- | ---------------------------------------- |
| `xor-single-byte`   | Exactly 1 byte | `out[i] = in[i] XOR key[0]`              |
| `xor-repeating-key` | 1–256 bytes    | `out[i] = in[i] XOR key[i mod len(key)]` |

Keys are supplied as hex through `--key` or `--key-file`. The CLI verifies the
round trip by default.

---

## 3. Cipher constructions

Cipher IDs are stored in the container. They are part of the on-disk format and
must never change.

| Cipher              | ID  | Key | Nonce/IV | Tag | Class                     |
| ------------------- | ---:| ---:| --------:| ---:| ------------------------- |
| `aes-256-gcm`       | 1   | 32  | 12       | 16  | Authenticated (default)   |
| `aes-128-gcm`       | 2   | 16  | 12       | 16  | Authenticated             |
| `chacha20-poly1305` | 3   | 32  | 12       | 16  | Authenticated             |
| `aes-256-cbc`       | 4   | 32  | 16       | 32  | Compatibility             |
| `aes-256-ctr`       | 5   | 32  | 16       | 32  | Compatibility             |
| `rc4`               | 6   | 32  | 16       | 32  | Legacy (`--allow-legacy`) |

All primitives come from maintained implementations: `crypto/aes`,
`crypto/cipher`, `crypto/rc4`, and
`golang.org/x/crypto/chacha20poly1305`. ByteForge does not implement ciphers
from scratch.

### 3.1 AEAD ciphers

`aes-256-gcm`, `aes-128-gcm`, and `chacha20-poly1305` use the Go `cipher.AEAD`
interface directly.

- Nonce: exactly 12 bytes, generated from the operating system CSPRNG for
  every encryption unless `--nonce` is supplied explicitly.
- Tag: 16 bytes, stored separately after the ciphertext.
- Ciphertext length equals plaintext length.
- AAD: the full container prefix (fixed header, salt, nonce) followed by the
  raw UTF-8 bytes of `--aad`, if any.
- Decryption calls `Open` on `ciphertext || tag`. Authentication is verified
  before any plaintext is returned.

Nonce uniqueness is mandatory. Never reuse a nonce with the same key. The CLI
warns when `--nonce` is used because explicit nonces are intended only for test
vectors and interoperability.

### 3.2 Compatibility ciphers: AES-256-CBC, AES-256-CTR, RC4

These modes are not authenticated by themselves. ByteForge always wraps them
with encrypt-then-MAC:

1. Derive two subkeys from the 32-byte input key using HKDF-SHA256:
   `HKDF-SHA256(secret=key, salt=nil, info="byteforge/<cipher>/v1", length=64)`.
   The first 32 bytes are the encryption key; the last 32 bytes are the MAC key.
   `<cipher>` is exactly `aes-256-cbc`, `aes-256-ctr`, or `rc4`.
2. Encrypt:
   - CBC: PKCS#7 padding to a multiple of 16 bytes, then AES-256-CBC with the
     16-byte IV.
   - CTR: AES-256-CTR with the 16-byte IV. No padding; ciphertext length equals
     plaintext length.
   - RC4: RC4 with the derived encryption key. The 16-byte value is carried as
     an IV for container symmetry and mixed into the MAC, but RC4 itself has no
     IV.
3. Compute the tag:
   `HMAC-SHA256(macKey, nonce || AAD || ciphertext)`.
   `AAD` already contains the container prefix, which itself contains the
   nonce; the nonce is therefore included twice. This is intentional and part
   of the v1 construction.
4. Store the 32-byte tag after the ciphertext.

Decryption verifies the tag with `hmac.Equal` before decrypting. CBC padding is
checked only after authentication. A padding error is reported as a
verification failure but is not reachable without a valid tag.

RC4 is obsolete. It is disabled unless `--allow-legacy` is supplied, and the
CLI prints a warning. CBC and CTR are compatibility modes; prefer AES-GCM for
new data.

---

## 4. Key derivation

| KDF             | ID  | Parameters                                                                                                 |
| --------------- | ---:| ---------------------------------------------------------------------------------------------------------- |
| `none`          | 0   | Explicit or generated key; salt length 0                                                                   |
| `scrypt-sha256` | 1   | scrypt N=2^15 (32768), r=8, p=1, dkLen=cipher key size (16 for `aes-128-gcm`, 32 otherwise), salt=16 bytes |

Password-based encryption always uses `scrypt-sha256`. The 16-byte salt is
generated from the OS CSPRNG and stored in the container. The scrypt parameters
are fixed by container version 1 and are not read from the file, so an attacker
cannot force arbitrary memory or CPU costs through the header. The derived key
length matches the selected cipher: 16 bytes for `aes-128-gcm`, 32 bytes for all
other ciphers.

- Passwords are used as raw bytes. `--password` uses the argument verbatim;
  `--password-file` and `--password-stdin` strip trailing CR/LF characters.
  Empty passwords are rejected.
- Password inputs are read with a 1 MiB safety limit.
- Derived and generated keys are never printed in summaries or diagnostics.
  Key-capable renderers include them in the rendered payload automatically.
  `--export-key FILE` is opt-in, forbidden for password-based encryption, and
  required when a random key is generated with a `raw`, `hex`, or `base64`
  renderer.
- Key-capable renderers emit the actual key as a second data declaration and
  trigger a secret-material warning. `--key-symbol NAME` names the declaration
  (default: `key`).
- Key files and exported keys are hex text. Exported key files use mode `0600`.

The scrypt cost is roughly 32 MiB of memory per derivation at these parameters.
This is intentional but may matter in constrained environments.

---

## 5. `BFRG` container version 1

Encrypted output is a self-describing container. All integers are unsigned
big-endian; there is no padding or alignment between fields.

```text
offset  size  field
0       4     magic "BFRG" (42 46 52 47)
4       1     version (1)
5       1     cipher id
6       1     kdf id
7       1     flags (must be 0)
8       1     salt length in bytes (0..64)
9       1     nonce length in bytes (1..32)
10      1     tag length in bytes (1..64)
11      1     reserved (must be 0)
12      8     ciphertext length in bytes (uint64)
20      S     salt (S = salt length; empty when kdf id is 0)
20+S    N     nonce / IV (N = nonce length)
20+S+N  C     ciphertext (C = ciphertext length)
...     T     authentication tag (T = tag length)
```

The file is exactly `20 + S + N + C + T` bytes. There are no trailing bytes and
no optional sections.

### 5.1 Authenticated data

The associated data for every cipher is:

```text
AAD = fixed header (20 bytes) || salt || nonce || extra
```

`extra` is the raw bytes of `--aad` (empty when the flag is absent). All header
fields, including lengths and algorithm IDs, are therefore authenticated
before use. The compatibility MAC construction hashes the nonce again as
described in §3.2.

### 5.2 Length rules by cipher

| Cipher                                            | Ciphertext length `C`                                  | Tag `T` |
| ------------------------------------------------- | ------------------------------------------------------ | -------:|
| `aes-256-gcm`, `aes-128-gcm`, `chacha20-poly1305` | equal to plaintext length                              | 16      |
| `aes-256-cbc`                                     | next multiple of 16, always at least one padding block | 32      |
| `aes-256-ctr`, `rc4`                              | equal to plaintext length                              | 32      |

### 5.3 Parser rules

`decrypt` and `inspect` use a strict parser. The following are rejected before
any plaintext is produced:

- fewer than 20 bytes, or a magic other than `BFRG`;
- a version other than 1;
- nonzero flags or a nonzero reserved byte;
- salt length above 64, nonce length 0 or above 32, tag length 0 or above 64;
- a ciphertext length larger than the configured input limit or the actual
  input size;
- a declared total size larger than the input (truncation) or smaller than the
  input (trailing bytes);
- an unknown cipher ID or KDF ID;
- a KDF/salt combination that contradicts the KDF ID during decryption;
- an authentication tag that does not verify.

Structural parse failures are processing failures (exit 1). An unsupported
algorithm or KDF selected from the header is a usage failure (exit 2).
Authentication failure is a verification failure (exit 4). Authentication
failures never write plaintext.

### 5.4 Versioning policy

- Version 1 is the only version this release writes or accepts.
- Cipher IDs, KDF IDs, field widths, the AAD construction, and fixed KDF
  parameters are frozen for version 1.
- Any incompatible change requires a new container version. A new version must
  not silently reuse version-1 semantics.
- Unknown versions, flags, IDs, and reserved values are rejected, not guessed.
- `inspect` parses containers strictly whenever the input starts with `BFRG`;
  it does not fall back to generic inspection for a malformed container.

---

## 6. Renderers

Renderers receive the final transformed bytes and non-secret metadata. They do
not change the operation or the selected codec/cipher.

| Identifier         | Output                                                                         |
| ------------------ | ------------------------------------------------------------------------------ |
| `raw`              | Exact bytes, no added newline                                                  |
| `hex`              | Uppercase hex plus one trailing LF; empty input produces empty output          |
| `base64`           | Standard padded Base64 plus one trailing LF; empty input produces empty output |
| `c-array`          | C/C++ `unsigned char` data declaration                                         |
| `csharp-array`     | C# `byte[]` data declaration                                                   |
| `nim-array`        | Nim `array[N, byte]` data declaration                                          |
| `go-bytes`         | Go `[]byte` data declaration                                                   |
| `python-bytes`     | Python bytes literal                                                           |
| `powershell-bytes` | PowerShell `[byte[]]` data declaration                                         |
| `vba-array`        | VBA `Byte` array declarations and assignments                                  |
| `vbs-array`        | VBScript `Array` data declaration                                              |
| `rust-array`       | Rust `[u8; N]` data declaration                                                |
| `javascript-array` | JavaScript `Uint8Array` data declaration                                       |
| `zig-array`        | Zig `[_]u8` data declaration                                                   |
| `json`             | JSON schema `1.0` with Base64 data                                             |

All language renderers are data declarations only. None emit a loader,
allocation helper, import, process-execution call, or injection scaffold.
Output is source text with a trailing LF.

### 6.1 `c-array`

- Default symbol: `data`; must match `[A-Za-z_][A-Za-z0-9_]*`.
- Default bytes per line: 16; allowed range 1–256.
- Header comments include the tool version, operation/format, byte count, and
  SHA-256 of the rendered bytes.
- Each byte is emitted as `0xHH,` and the declaration ends with `};`.
- Empty input emits a one-byte placeholder `{ 0x00 }` with a comment stating
  that the input was empty.
- Output is a data declaration only. It contains no loader, allocation,
  injection, or execution code.

### 6.2 `python-bytes`

- Default symbol: `data`; `_` is normalized to `data`. Other names must be
  valid Python identifiers.
- Default bytes per line: 16; allowed range 1–256.
- Output is `symbol = (` followed by `b"\xhh..."` chunks and a closing `)`.
- Empty input emits `symbol = b""`.
- Output is a data literal only; it contains no execution code.

### 6.3 Other language renderers

These renderers follow the same data-only contract and share these rules:

- Default symbol: `data`. Symbols must match `[A-Za-z_][A-Za-z0-9_]*`.
  `powershell-bytes` also accepts a leading `$` and emits exactly one.
- Default bytes per line: 16; allowed range 1–256. VBA groups assignments on a
  line with `:`; VBScript groups values with `_` line continuations.
- A header comment records the tool version, and when an operation is active
  also the operation, format, byte count, and SHA-256.
- Empty input emits a syntactically valid empty declaration rather than a
  fabricated zero byte.

| Identifier         | Declaration form                                            | Empty input                        |
| ------------------ | ----------------------------------------------------------- | ---------------------------------- |
| `csharp-array`     | `byte[] data = new byte[] { 0x.., };`                       | `byte[] data = new byte[0];`       |
| `nim-array`        | `const data: array[N, byte] = [0x..'u8, ...]`               | `const data: array[0, byte] = []`  |
| `go-bytes`         | `var data = []byte{ 0x.., }`                                | `var data = []byte{}`              |
| `powershell-bytes` | `[byte[]] $data = @(0x.., ...)`                             | `[byte[]] $data = @()`             |
| `vba-array`        | `Dim data(0 To N-1) As Byte` plus `data(i) = n` assignments | `Dim data() As Byte`               |
| `vbs-array`        | `data = Array(0, 65, ...)`                                  | `data = Array()`                   |
| `rust-array`       | `pub static data: [u8; N] = [0x.., ...];`                   | `pub static data: [u8; 0] = [];`   |
| `javascript-array` | `const data = new Uint8Array([0x.., ...]);`                 | `const data = new Uint8Array([]);` |
| `zig-array`        | `pub const data = [_]u8{ 0x.., ... };`                      | `pub const data = [_]u8{};`        |

VBA and VBScript receive decimal byte values `0`–`255`, which avoids
signed-integer overflow for values above `127`.

### 6.4 Key declarations

On `encrypt`, a key-capable source renderer emits the payload declaration
followed by a blank line and a second declaration using the same renderer. This
is automatic; there is no separate key-output flag. The key declaration:

- uses `--key-symbol` (default `key`);
- omits the operation, format, input size, and SHA-256 line, so the output does
  not expose a digest of the secret;
- accepts the same `--bytes-per-line` grouping and symbol rules as the payload;
- must not reuse the payload symbol.

The key-capable identifiers are `c-array`, `csharp-array`, `nim-array`,
`go-bytes`, `python-bytes`, `powershell-bytes`, `vba-array`, `vbs-array`,
`rust-array`, `javascript-array`, `zig-array`, and `json`. `raw`, `hex`, and
`base64` never include a key because concatenating two values would make the
output ambiguous; use `--export-key FILE` with those renderers.

For password-based encryption the rendered key is the scrypt output, not the
password. Code using it directly must read the container's salt, nonce,
ciphertext, and tag and skip the KDF step.

### 6.5 `json` schema 1.0

The document is pretty-printed with two-space indentation and a trailing LF.
`data` is Base64 of the bytes passed to the renderer (encoded text for
`encode`, ciphertext for `encrypt`, plaintext for `decrypt`).

```json
{
  "schemaVersion": "1.0",
  "tool": "byteforge",
  "version": "0.1.0",
  "timestamp": "2026-01-01T00:00:00Z",
  "operation": "encode",
  "format": "base64",
  "encoding": "base64",
  "cipher": "",
  "inputSize": 9,
  "outputSize": 13,
  "inputSha256": "...",
  "outputSha256": "...",
  "verification": "passed",
  "dataEncoding": "base64",
  "data": "Qnl0ZUZvcmdl"
}
```

Empty optional fields are omitted. `timestamp` appears only with `--timestamp`.
`outputSize` and `outputSha256` describe the rendered data in `data`, not the
original input.

For encryption with the `json` renderer, a `key` object is always added:

```json
{
  "key": {
    "symbol": "key",
    "encoding": "base64",
    "size": 32,
    "data": "ERERERERERERERERERERERERERERERERERERERERERE="
  }
}
```

---

## 7. Golden vectors

All vectors below are reproduced by the test suite from files in
[`testdata/containers/`](../testdata/containers). Plaintext is always the
9-byte ASCII string `ByteForge`
([`testdata/plaintext/ByteForge.bin`](../testdata/plaintext/ByteForge.bin)).

Shared key (32 bytes):

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

### 7.1 AES-256-GCM, explicit key

- File: `testdata/containers/gcm-key.bf`
- Cipher ID 1, KDF 0, salt empty, nonce 12 bytes, tag 16 bytes
- SHA-256: `ae44837b860d22d241f57410e31749bcc9bad6a407bfd5f29a12f1d1872fe8c9`

```text
4246524701010000000c10000000000000000009000102030405060708090a0b057ba27e838ab07ce8842e583cd80718274a78877e27bfb54a
```

Field split: ciphertext `057ba27e838ab07ce8`, tag
`42e583cd80718274a78877e27bfb54a`.

### 7.2 AES-256-GCM with AAD

- File: `testdata/containers/gcm-key-aad.bf`
- AAD: `context=v1`
- Same key, nonce, and plaintext as §7.1
- SHA-256: `b6f008f95e6e43601fc318bb5c769e6e6e9efc1d2f1bbb07aafc7b496065f2f9`

```text
4246524701010000000c10000000000000000009000102030405060708090a0b057ba27e838ab07ce89062600198793331909c9e0276a292bd
```

### 7.3 AES-128-GCM, explicit key

- File: `testdata/containers/gcm128-key.bf`
- Key: `000102030405060708090a0b0c0d0e0f`
- Cipher ID 2, KDF 0, nonce 12 bytes
- SHA-256: `7e47e826a9293f7aa5bd1db658f0ea2410233fb45f66426555055bb193cb571e`

```text
4246524701020000000c10000000000000000009000102030405060708090a0bd115d3ab207485332e6f1922f390fbb773aa3c82d0603cac6f
```

### 7.4 ChaCha20-Poly1305, explicit key

- File: `testdata/containers/chacha-key.bf`
- Cipher ID 3, KDF 0, shared 32-byte key and 12-byte nonce
- SHA-256: `1fee755f977abde6baf5a0a4f7ddd2ead113ba5f727742e967611d0742898535`

```text
4246524701030000000c10000000000000000009000102030405060708090a0bcb827c656f78d727d2d9810e37135b729d5017b575b9ab8043
```

### 7.5 AES-256-CBC + HMAC-SHA256, explicit key

- File: `testdata/containers/cbc-key.bf`
- Cipher ID 4, KDF 0, shared 32-byte key and 16-byte IV
- SHA-256: `52b28e53244e1501250f51021b58a0203754dfe482b38c05e4c9b45622e21ba9`

```text
4246524701040000001020000000000000000010000102030405060708090a0b0c0d0e0fe8925a5eae451290bbd3e60bd95897ef045915fd7b0c917d48789ecfe339b0d8764c45d1f38fb258c5238ee86c0c7e85
```

Field split: ciphertext is 16 bytes
(`e8925a5eae451290bbd3e60bd95897ef`), tag is 32 bytes
(`045915fd7b0c917d48789ecfe339b0d8764c45d1f38fb258c5238ee86c0c7e85`).

### 7.6 Password-based AES-256-GCM

- File: `testdata/containers/gcm-password.bf`
- Password: `correct horse battery staple`
- Salt (16 bytes): `101112131415161718191a1b1c1d1e1f`
- KDF ID 1 (`scrypt-sha256`), cipher ID 1, 12-byte nonce
- Derived key:
  `4422cc8b14ecaf05e5b234429eac95c3594a6f75c9bdd032fedf5416db8dae48`
- SHA-256: `a2e0553480bb2105b18d337397b7cd800b912ad79c20100f4b05367df4b533cc`

```text
4246524701010100100c10000000000000000009101112131415161718191a1b1c1d1e1f000102030405060708090a0b71f766f71bec193f96d2693af7b8c8c26c2317f16823c375ec
```

The salt is normally random; this vector fixes it so the derived key and
container are reproducible. In normal use, a fresh salt and nonce are
generated for every encryption.

### 7.7 Codec vectors

[`testdata/codecs.json`](../testdata/codecs.json) stores the byte-exact output
as `encodedHex`; `encoded` is included when the output is valid UTF-8. For the
7-byte input `00 01 02 7f 80 fe ff`:

| Codec            | Output                                                           |
| ---------------- | ---------------------------------------------------------------- |
| `hex`            | `0001027F80FEFF`                                                 |
| `base64`         | `AAECf4D+/w==`                                                   |
| `base64url`      | `AAECf4D-_w==`                                                   |
| `base32`         | `AAAQE74A737Q====`                                               |
| `ascii85`        | `!!*.NJH#Q`                                                      |
| `raw`            | bytes `00 01 02 7f 80 fe ff`                                     |
| `decimal`        | `0 1 2 127 128 254 255`                                          |
| `octal`          | `000 001 002 177 200 376 377`                                    |
| `binary`         | `00000000 00000001 00000010 01111111 10000000 11111110 11111111` |
| `c-escaped`      | `"\x00\x01\x02\x7f\x80\xfe\xff"`                                 |
| `unicode-escape` | `\u0000\u0001\u0002\u007f\u0080\u00fe\u00ff`                     |

Typed vectors:

| Codec  | Input                              | Output                                 |
| ------ | ---------------------------------- | -------------------------------------- |
| `mac`  | `001122aabbcc`                     | `00:11:22:AA:BB:CC`                    |
| `ipv4` | `c0a80101`                         | `192.168.1.1`                          |
| `ipv6` | `20010db8000000000000000000000001` | `2001:db8::1`                          |
| `uuid` | `00112233445566778899aabbccddeeff` | `00112233-4455-6677-8899-aabbccddeeff` |

Sequence vectors:

| Codec       | Input                                                              | Output                                                                       |
| ----------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `mac-list`  | `001122aabbccdeadbeef0001`                                         | `00:11:22:AA:BB:CC\nDE:AD:BE:EF:00:01`                                       |
| `ipv4-list` | `c0a8010108080808`                                                 | `192.168.1.1\n8.8.8.8`                                                       |
| `ipv6-list` | `20010db800000000000000000000000100000000000000000000000000000001` | `2001:db8::1\n::1`                                                           |
| `uuid-list` | `00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100` | `00112233-4455-6677-8899-aabbccddeeff\nffeeddcc-bbaa-9988-7766-554433221100` |

`\n` in the table denotes the single LF separator emitted between values; no
trailing newline is added.

---

## 8. Inspect output

`inspect` reports size, SHA-256, and Shannon entropy in bits per byte. Entropy
is descriptive only; it says nothing about safety, correctness, or whether the
data is executable. When the input starts with `BFRG`, strict container
metadata is added: version, cipher ID/name, KDF ID/name, salt length, nonce
length and hex, ciphertext length, tag length, and total size. The nonce is not
secret and is safe to display; keys, passwords, and derived keys are never
displayed.

## 9. Explicit payload padding

Padding is not a codec, cipher, transform, or renderer. It is an optional
payload stage requested with `--pad`, applied at the operation boundary, and
reported in the summary. Nothing is padded unless the caller asks for it.

| `--pad` value | Fill byte(s)                                                |
| ------------- | ----------------------------------------------------------- |
| `none`        | None; reject a payload that is not already aligned           |
| `nop`         | `0x90`                                                      |
| `zero`        | `0x00`                                                      |
| `random`      | CSPRNG bytes from `crypto/rand`                             |
| `HEX`         | Repeating caller-supplied bytes, for example `CC` or `9090` |

Parsing rules:

- Bare `--pad` normalizes to `--pad=random`.
- `--pad-to` alone also enables padding with the `random` fill.
- Hex patterns must contain whole bytes and at least one byte. They repeat
  cyclically and truncate to the exact number of bytes needed.
- An already-aligned payload is unchanged. Padding adds between 1 and
  `multiple-1` bytes, never a full extra block.
- `none` is an explicit alignment assertion: a misaligned payload is a usage
  error (exit 2). Omitting both padding flags preserves the previous behavior.

Target and gating:

On `encode`, padding is valid only for the eight fixed-width codecs. Any other
encoding ignores it and prints:

```text
[!] --pad has no effect for encoding 'base64'; ignoring
```

`--pad-to` likewise has no effect on a non-fixed-width encoding.

For the fixed-width codecs the target is always the codec width or chunk size;
`--pad-to`, when supplied, must match it. For `decode`, `decrypt`, `encrypt`,
`transform`, and `untransform`, the target is `--pad-to` when supplied and 16
bytes otherwise.

Single-value codecs accept exactly one value:

- input shorter than the width is filled up to exactly one value;
- input equal to the width is unchanged;
- input longer than the width is a usage error (exit 2), even if it is a
  multiple of the width, because padding cannot split or repeat data. The error
  names the matching `-list` codec and the number of values it would produce.

List codecs fill only the final partial chunk:

- `remainder = len(input) % chunk`; when `remainder == 0` nothing is added;
- otherwise exactly `chunk - remainder` bytes are appended.

The oversized single-value check runs before padding, so the command never
reports padding bytes it cannot use:

```text
[ERROR] ipv6 requires exactly 16 bytes, got 276; --pad cannot truncate data.
        Use --encoding ipv6-list --pad nop to encode as a sequence of 18 addresses.
```

Successful padding and no-padding cases are reported as:

```text
[!] input 276 bytes padded by +12 bytes (nop/0x90) → total 288 bytes (18 chunks)
[*] no padding needed (276 bytes, 69 chunks)
[*] no padding needed
```

The method label is `nop/0x90`, `zero/0x00`, `random`, or `hex/HEX`. The first
line is a warning because padding changes the payload; the no-padding lines are
routine status.

Placement:

| Command       | Padding point                                      |
| ------------- | -------------------------------------------------- |
| `encode`      | Input is padded before `codec.Encode`              |
| `decode`      | Output is padded after `codec.Decode`              |
| `encrypt`     | Plaintext is padded before container construction  |
| `decrypt`     | Plaintext is padded after authentication/decrypt   |
| `transform`   | Input is padded before the XOR transform           |
| `untransform` | Output is padded after the XOR transform           |

Padding is a one-way payload change at that boundary. Reverse operations do not
detect or remove it, because arbitrary binary data carries no reliable padding
marker. For example, `encrypt --pad zero --pad-to 16` followed by `decrypt`
returns the padded plaintext, not the original unpadded length. Callers that
need the original bytes must record the original length or use a length-carrying
container of their own.

Padding is deliberately compatible with the lossless `-list` codecs: padding to
the element width first keeps the resulting sequence valid, and decoding it
yields exactly the padded payload.

```bash
# List codec: fill the final partial chunk (276 -> 288 bytes, 18 IPv6 values)
byteforge encode --file calc.bin --encoding ipv6-list --pad nop -o addresses.txt

# List codec already aligned: no padding needed (276 % 4 == 0)
byteforge encode --file calc.bin --encoding ipv4-list --pad nop

# Single value: exact match, no padding needed
byteforge encode --hex c0a80101 --encoding ipv4 --pad nop

# Single value: pad the missing tail up to exactly 16 bytes
byteforge encode --hex 20010db8 --encoding ipv6 --pad zero

# Single value too large: hard error, suggests ipv6-list
byteforge encode --file calc.bin --encoding ipv6 --pad nop

# Non-fixed-width encoding: --pad is ignored with a warning
byteforge encode --hex 00010203 --encoding base64 --pad nop
```
