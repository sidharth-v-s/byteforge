package cli

const rootUsage = `ByteForge — binary transformation tool (data only)

Usage:
  byteforge <command> [options]

Commands:
  formats      List supported codecs, transforms, ciphers, and renderers
  encode       Encode input with a representation codec
  decode       Decode a representation back to bytes
  encrypt      Encrypt input into a versioned ByteForge container
  decrypt      Decrypt a ByteForge container
  transform    Apply a reversible XOR transform
  untransform  Apply the same XOR transform (XOR is symmetric)
  inspect      Show size, hashes, entropy, and container metadata
  verify       Compare files or verify a SHA-256 digest
  version      Print version information
  help         Show this help

Common options (place them after the command):
  -f, --file FILE        Input file (binary-safe)
  -s, --hex HEX          Input as a hexadecimal string (mutually exclusive with --file)
  -o, --output FILE      Write payload to FILE (default: stdout)
      --force            Overwrite an existing output file
      --renderer NAME    Output renderer (default: raw; see 'byteforge formats')
      --symbol NAME      Symbol for data-declaration renderers (default: data)
      --bytes-per-line N Bytes per line for array renderers (default: 16)
      --pad MODE         Explicit payload padding: none|nop|zero|random|HEX
                          (encode: fixed-width codecs only)
      --pad-to N         Padding multiple (default: fixed codec width or 16)
      --verbose, -v      Verbose diagnostics (never prints secrets)
      --no-color         Disable ANSI color
      --no-banner        Suppress the startup banner
      --timestamp        Include a timestamp in reports
      --max-input N      Maximum input bytes (default: 64 MiB)
      --help             Command help

Safety boundary:
  ByteForge transforms and inspects data only. It never executes, loads,
  injects, or delivers processed bytes. Generated C, C#, Nim, Go, Python,
  PowerShell, VBA, VBS, Rust, JavaScript, and Zig output contains data
  declarations only.

Renderer identifiers:
  raw, hex, base64, json
  c-array, csharp-array, nim-array, go-bytes, python-bytes,
  powershell-bytes, vba-array, vbs-array, rust-array,
  javascript-array, zig-array

Exit codes:
  0 success | 1 processing failure | 2 usage/unsupported | 3 I/O
  4 verification or authentication failure

Examples:
  byteforge encode --file input.bin --encoding base64 --output payload.txt
  byteforge decode --file payload.txt --encoding base64 --output recovered.bin
  byteforge encrypt --file input.bin --password-stdin --output sample.bf
  byteforge decrypt --file sample.bf --password-stdin --output recovered.bin
  byteforge encode --file address.bin --encoding ipv4
  byteforge formats
`

const encodeUsage = `Usage: byteforge encode [options]

Encode bytes with a representation codec, then render the result.

Options:
  -f, --file FILE         Input file
  -s, --hex HEX           Input as a hexadecimal string
      --encoding NAME     Codec identifier (required; see 'byteforge formats')
      --renderer NAME     Output renderer (default: raw; see 'byteforge formats')
      --symbol NAME       Symbol for data-declaration renderers
      --bytes-per-line N  Bytes per line (default: 16)
      --pad MODE          Pad fixed-width codecs: nop|zero|random|HEX
                          (default: random when --pad is given without a value;
                          other encodings ignore --pad with a warning)
      --pad-to N          Padding multiple; must match the codec width
      --no-verify         Skip round-trip verification
  -o, --output FILE       Output file (default: stdout)
      --force             Overwrite an existing output file
      --verbose, -v       Verbose diagnostics
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --timestamp         Include a timestamp in reports
      --max-input N       Maximum input bytes (default: 64 MiB)

Examples:
  byteforge encode --file input.bin --encoding base64 --output payload.txt
  byteforge encode --file addr.bin --encoding ipv4
  byteforge encode --file addresses.bin --encoding ipv4-list   # one value per line
  byteforge encode --hex 48656c6c6f --encoding hex
  byteforge encode --file input.bin --encoding hex --renderer c-array --symbol payload
  byteforge encode --file calc.bin --encoding ipv6-list --pad nop
  byteforge encode --hex 20010db8 --encoding ipv6 --pad zero
  byteforge encode --hex 00112233445566 --encoding mac-list --pad zero
`

const decodeUsage = `Usage: byteforge decode [options]

Decode a representation back to bytes, then render the result.

Options:
  -f, --file FILE         File containing the encoded text
  -s, --hex HEX           Hexadecimal bytes of the encoded text
      --encoding NAME     Codec identifier (required; see 'byteforge formats')
      --renderer NAME     Output renderer (default: raw; see 'byteforge formats')
      --symbol NAME       Symbol for data-declaration renderers
      --bytes-per-line N  Bytes per line (default: 16)
      --pad MODE          Pad after decoding: none|nop|zero|random|HEX
                          (default: random when --pad is given without a value)
      --pad-to N          Padding multiple (default: codec width or 16)
      --no-verify         Skip round-trip verification
  -o, --output FILE       Output file (default: stdout)
      --force             Overwrite an existing output file
      --verbose, -v       Verbose diagnostics
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --timestamp         Include a timestamp in reports
      --max-input N       Maximum input bytes (default: 64 MiB)

Examples:
  byteforge decode --file payload.txt --encoding base64 --output recovered.bin
  byteforge decode --file uuid.txt --encoding uuid
  byteforge decode --file payload.hex --encoding hex --renderer c-array --pad nop
`

const encryptUsage = `Usage: byteforge encrypt [options]

Encrypt raw input into a versioned ByteForge container (BFRG v1).

Key sources (choose one):
      --password TEXT       Password (WARNING: visible in the process list)
      --password-file FILE  Read the password from FILE
      --password-stdin      Read the password from stdin
      --key HEX             Explicit key as hex (size depends on cipher)
      --key-file FILE       Read the explicit key as hex from FILE
      --export-key FILE     Export the key to FILE (opt-in; contains a secret)

  Key output:
      --key-symbol NAME     Symbol for the key declaration (default: key)

  Key-capable renderers (c-array, csharp-array, nim-array, go-bytes,
  python-bytes, powershell-bytes, vba-array, vbs-array, rust-array,
  javascript-array, zig-array, and json) always include the key in the
  output. raw, hex, and base64 cannot carry a key; for a generated key with
  those renderers, pass --export-key FILE.

Options:
  -f, --file FILE         Input file
  -s, --hex HEX           Input as a hexadecimal string
      --cipher NAME       aes-256-gcm (default) | aes-128-gcm | chacha20-poly1305
                          | aes-256-cbc | aes-256-ctr | rc4
      --nonce HEX         Explicit nonce/IV (tests/interoperability only)
      --aad TEXT          Additional authenticated data (must be repeated at decrypt)
      --allow-legacy      Permit legacy algorithms (currently rc4)
      --renderer NAME     Output renderer (default: raw; see 'byteforge formats')
      --symbol NAME       Symbol for data-declaration renderers
      --bytes-per-line N  Bytes per line (default: 16)
      --pad MODE          Pad plaintext before encryption: none|nop|zero|random|HEX
                          (default: random when --pad is given without a value)
      --pad-to N          Padding multiple (default: 16)
      --no-verify         Skip internal decrypt verification
  -o, --output FILE       Output file (default: stdout)
      --force             Overwrite an existing output file
      --verbose, -v       Verbose diagnostics
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --timestamp         Include a timestamp in reports
      --max-input N       Maximum input bytes (default: 64 MiB)

Examples:
  byteforge encrypt --file input.bin --password-stdin --output sample.bf
  printf 'correct horse battery staple' | byteforge encrypt --file input.bin --password-stdin --output sample.bf
  byteforge encrypt --file input.bin --key 000102...1f --output sample.bf
  byteforge encrypt --file input.bin --password-stdin --renderer c-array --output sample.c
  byteforge encrypt --file input.bin --password-stdin --renderer javascript-array --output payload.js
`

const decryptUsage = `Usage: byteforge decrypt [options]

Decrypt a versioned ByteForge container (BFRG v1).

Options:
  -f, --file FILE         Encrypted container file
  -s, --hex HEX           Container as a hexadecimal string
      --password TEXT     Password (WARNING: visible in the process list)
      --password-file FILE
      --password-stdin    Read the password from stdin
      --key HEX           Explicit key as hex
      --key-file FILE     Read the explicit key as hex from FILE
      --aad TEXT          Additional authenticated data used at encryption
      --allow-legacy      Permit legacy algorithms (currently rc4)
      --renderer NAME     Output renderer (default: raw; see 'byteforge formats')
      --symbol NAME       Symbol for data-declaration renderers
      --bytes-per-line N  Bytes per line (default: 16)
      --pad MODE          Pad plaintext after decryption: none|nop|zero|random|HEX
                          (default: random when --pad is given without a value)
      --pad-to N          Padding multiple (default: 16)
      --no-verify         Skip re-encryption verification
  -o, --output FILE       Output file (default: stdout)
      --force             Overwrite an existing output file
      --verbose, -v       Verbose diagnostics
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --timestamp         Include a timestamp in reports
      --max-input N       Maximum input bytes (default: 64 MiB)

Authentication is verified before any plaintext is returned or written.

Examples:
  byteforge decrypt --file sample.bf --password-stdin --output recovered.bin
  byteforge decrypt --file sample.bf --key 000102...1f --output recovered.bin
`

const transformUsage = `Usage: byteforge transform [options]
       byteforge untransform [options]

Apply a reversible XOR transform. XOR is symmetric, so transform and
untransform perform the same operation. XOR is obfuscation, not encryption.

Options:
  -f, --file FILE         Input file
  -s, --hex HEX           Input as a hexadecimal string
      --transform NAME    xor-single-byte | xor-repeating-key (required)
      --key HEX           Transform key as hex (required)
      --key-file FILE     Read the transform key as hex from FILE
      --renderer NAME     Output renderer (default: raw; see 'byteforge formats')
      --symbol NAME       Symbol for data-declaration renderers
      --bytes-per-line N  Bytes per line (default: 16)
      --pad MODE          Pad payload around the transform: none|nop|zero|random|HEX
                          (default: random when --pad is given without a value)
      --pad-to N          Padding multiple (default: 16)
      --no-verify         Skip double-application verification
  -o, --output FILE       Output file (default: stdout)
      --force             Overwrite an existing output file
      --verbose, -v       Verbose diagnostics
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --timestamp         Include a timestamp in reports
      --max-input N       Maximum input bytes (default: 64 MiB)

Examples:
  byteforge transform --file input.bin --transform xor-single-byte --key 5a
  byteforge transform --file input.bin --transform xor-repeating-key --key deadbeef
`

const inspectUsage = `Usage: byteforge inspect [options]

Show size, SHA-256, entropy, and non-secret container metadata. If the input
begins with the ByteForge magic, the container is strictly parsed and malformed
containers are reported as errors.

Options:
  -f, --file FILE         Input file
  -s, --hex HEX           Input as a hexadecimal string
      --json              Emit machine-readable JSON
  -o, --output FILE       Output file (default: stdout)
      --force             Overwrite an existing output file
      --verbose, -v       Verbose diagnostics and bounded hex preview
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --max-input N       Maximum input bytes (default: 64 MiB)

Examples:
  byteforge inspect --file sample.bf
  byteforge inspect --file input.bin --verbose
`

const verifyUsage = `Usage: byteforge verify [options]

Compare two files byte-for-byte, or verify a file's SHA-256 digest.

Modes:
      --original FILE     Original file
      --recovered FILE    Recovered file to compare
  or
      --file FILE         File to hash
      --sha256 HEX        Expected SHA-256 (case-insensitive)

Options:
      --verbose, -v       Verbose diagnostics
      --no-color          Disable ANSI color
      --no-banner         Suppress the startup banner
      --max-input N       Maximum input bytes (default: 64 MiB)

Examples:
  byteforge verify --original input.bin --recovered recovered.bin
  byteforge verify --file sample.bf --sha256 9f86d081884c7d65...
`

const formatsUsage = `Usage: byteforge formats [options]

List supported representation codecs, reversible transforms, cryptographic
algorithms, legacy algorithms, and output renderers separately.

Options:
      --json              Emit machine-readable JSON
      --verbose, -v       Include parameter details
      --no-color          Disable ANSI color

Examples:
  byteforge formats
  byteforge formats --json
`
