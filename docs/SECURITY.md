# ByteForge Security

ByteForge is a local data-transformation tool. This document states what it
protects, what it does not protect, and how to use it without creating a false
sense of safety.

Security claims here are limited to the implemented construction. XOR and RC4
are explicitly not suitable for protecting sensitive data. A successful decode
or a high entropy reading is not evidence that data is safe or trustworthy.

---

## 1. Scope and safety boundary

ByteForge transforms bytes. It has no code path that executes, loads, injects,
maps, or delivers the processed data. Generated language output (C, C#, Nim, Go,
Python, PowerShell, VBA, VBS, Rust, JavaScript, and Zig) is a data declaration
only, with no loader, allocation, injection, or execution scaffolding.

This boundary is a product invariant, not a sandbox. ByteForge cannot stop a
user from compiling or evaluating generated source elsewhere. It also cannot
make untrusted data safe to run; it only changes its representation or protects
it with cryptography.

Out of scope:

- malware analysis verdicts, shellcode detection, or payload classification;
- endpoint protection, sandboxing, or privilege separation;
- network transport, key exchange, or remote attestation;
- secure deletion from disks, backups, swap, or memory;
- protection against a compromised host, kernel, Go runtime, or toolchain;
- side-channel hardening against a local attacker who can observe memory or
  precise timing.

---

## 2. Threat model

### Assets

- plaintext and its representation;
- passwords, explicit keys, derived keys, and exported key files;
- integrity of the encrypted container and the decoded output;
- user trust in the reported operation and verification result.

### Adversary capabilities considered

- can read, copy, truncate, reorder, or modify encrypted files;
- can choose container headers, salts, nonces, ciphertext lengths, tags, and
  AAD values;
- can guess passwords offline;
- can observe command-line arguments and environment on a shared host;
- can race output-file creation.

### Adversary capabilities not addressed

- read or write access to process memory, the Go runtime, or the kernel;
- control of the ByteForge binary, its dependencies, or the build toolchain;
- a compromised random-number generator;
- coercion of the user or disclosure of the password through other channels;
- traffic analysis of file sizes and operation timing on the local host.

### Security goals

1. Confidentiality of plaintext against an attacker who does not know the key
   or password, for modern ciphers used correctly.
2. Integrity and authenticity of the container, including its header, salt,
   nonce, ciphertext, and caller-supplied AAD.
3. No plaintext release before authentication succeeds.
4. No silent overwrite of output or key files.
5. No secret key material in routine reports or summaries. Key-capable renderers
   deliberately include the key in the payload and warn that the output is
   secret.
6. Strict parsing of file-controlled lengths and identifiers.

---

## 3. Cryptographic design

### Modern ciphers

The default is AES-256-GCM. AES-128-GCM and ChaCha20-Poly1305 are also
available. All use maintained Go implementations and provide authenticated
encryption with a 16-byte tag.

- A fresh 12-byte nonce is generated from the OS CSPRNG for every encryption.
- The 20-byte header, salt, nonce, and `--aad` bytes are authenticated as
  associated data.
- Decryption verifies the tag before returning plaintext.
- Nonce reuse with the same key is catastrophic for GCM and ChaCha20-Poly1305.
  Do not use `--nonce` outside tests and interoperability work. The CLI warns
  whenever it is supplied.

### Compatibility ciphers

AES-256-CBC, AES-256-CTR, and RC4 are not authenticated by themselves.
ByteForge wraps each with encrypt-then-MAC:

- HKDF-SHA256 derives independent 32-byte encryption and MAC keys from the
  32-byte input key, using `info = "byteforge/<cipher>/v1"` and an empty salt.
- HMAC-SHA256 covers `nonce || AAD || ciphertext`.
- The tag is verified with `hmac.Equal` before decryption.
- CBC uses PKCS#7 padding and checks it only after authentication. This
  prevents a padding-oracle signal from untrusted ciphertext.

These modes are compatibility constructs. They do not interoperate with tools
that expect bare CBC/CTR, and they should not be preferred over AES-GCM. RC4 is
obsolete, disabled by default, and must be enabled with `--allow-legacy`; even
with HMAC protection, it is not recommended.

### Key derivation

Password-based encryption uses scrypt with N=2^15, r=8, p=1, a 16-byte random
salt, and a 32-byte output key. Parameters are fixed by container version 1 and
are not attacker-controlled.

scrypt raises the cost of offline guessing but cannot rescue a weak password.
ByteForge does not estimate password strength, enforce composition rules, or
rate-limit guesses. Use a long, unique password or, preferably, a high-entropy
key from a password manager or key file.

### Randomness

Keys, salts, and nonces come from `crypto/rand`, which uses the operating
system CSPRNG. Random failure is treated as a processing error; ByteForge does
not fall back to a weaker source.

---

## 4. Container parsing defenses

The `BFRG` v1 parser:

- checks the magic and exact version before interpreting fields;
- rejects nonzero flags and reserved bytes;
- bounds salt, nonce, and tag lengths before allocation or slicing;
- rejects a declared ciphertext length larger than the configured input limit
  or the actual input;
- checks the exact total size, rejecting both truncation and trailing bytes;
- rejects unknown cipher IDs, KDF IDs, and combinations that contradict the
  stored KDF;
- authenticates the fixed header, salt, nonce, and caller AAD, so header
  tampering is detected by the cipher;
- never writes plaintext on authentication failure.

Structural parse errors (exit 1) and authentication failures (exit 4) are
reported separately. This distinction reveals whether a container is
structurally well-formed, but not any plaintext, key, or password. It is not a
padding oracle: CBC padding is checked only after a valid MAC.

`inspect` parses strictly whenever the input begins with `BFRG`. It does not
silently treat a malformed container as arbitrary data.

### AAD is not a key

`--aad` binds context to a ciphertext. It must be supplied identically at
decryption. It is not secret, not a substitute for a key, and not a place for
passwords. Changing it causes authentication failure by design.

---

## 5. Secret handling

### Passwords

- `--password TEXT` is visible in the process list and may be retained in shell
  history. Prefer `--password-file FILE` or `--password-stdin`.
- `--password-file` and `--password-stdin` strip trailing CR/LF only. Other
  whitespace is part of the password.
- Empty passwords are rejected.
- Passwords are never printed, hashed into reports, or included in JSON output.

### Keys

- Explicit keys are supplied as hex via `--key` or `--key-file`.
- If no key source is given during encryption, a random key is generated. With a
  key-capable renderer the key is included in the output; with `raw`, `hex`, or
  `base64`, `--export-key FILE` is required so the ciphertext is not left
  unrecoverable.
- `--export-key` is forbidden with password-based encryption because the
  password is the key source. Key-capable renderers include the derived key
  automatically.
- Encryption with a key-capable renderer always embeds the actual key beside the
  ciphertext, so the output is secret material; the command warns on stderr. It
  covers `c-array`, `csharp-array`, `nim-array`, `go-bytes`, `python-bytes`,
  `powershell-bytes`, `vba-array`, `vbs-array`, `rust-array`,
  `javascript-array`, `zig-array`, and `json`.
- Generated source files that contain the key, and exported key files, are
  written with mode `0600`; export triggers an explicit warning that the file
  contains a secret.
- Key export uses the same non-overwrite rules as other output. `--export-key`
  may not share a path with `--output`.

### Memory and erasure

Keys, passwords, derived keys, and plaintext exist in Go-managed memory. Go
does not guarantee zeroization, and the garbage collector, operating system,
swap, hibernation files, crash dumps, or backups may retain copies. ByteForge
does not lock pages or attempt secure memory wiping.

Deleting a key file or container does not guarantee secure erasure. Use
full-disk encryption and an appropriate key-management process if that matters.

### Reporting

Routine summaries include sizes, hashes, algorithm identifiers, KDF name, key
source description, and verification status. They never include the password,
explicit key, derived key, or exported key bytes. Key-capable renderers place the
key in the payload output, not in the summary, and the summary reports only that
key material is included.

Verbose mode prints bounded hex previews of input and output (first 64 bytes).
Those previews can contain sensitive plaintext or ciphertext-derived data. Do
not enable `--verbose` when terminal logs or CI output are retained somewhere
you would not store the payload. Verbose mode still never prints key material.

---

## 6. Output and filesystem safety

- Payload bytes go to stdout or `--output`; diagnostics go to stderr. Raw
  binary output is never mixed with status text.
- Raw output to a terminal triggers a warning because it can corrupt the
  display and expose bytes on screen.
- Existing files are not overwritten without `--force`. Non-forced writes use
  `O_EXCL` with mode `0600`.
- Forced writes use a temporary file in the destination directory, `fsync`,
  and an atomic rename where supported. Failed writes remove the partial file.
- Key files and output files may still be readable by administrators, backups,
  or synchronization tools. Directory permissions matter as much as file mode.
- Do not write secrets to a world-writable directory or a path controlled by
  another user.

---

## 7. What ByteForge does not prove

- **Decoding is not validation.** A successful Base64 or hex decode only means
  the bytes were syntactically valid. It says nothing about intent or safety.
- **Entropy is not a safety signal.** Shannon entropy is a descriptive statistic
  over byte frequencies. Encrypted data and compressed data look similar; low
  entropy is not proof of benign content, and high entropy is not proof of
  malware.
- **A hash is not authentication.** SHA-256 in reports detects accidental
  changes only when compared with a trusted expected value. It does not prove
  who created a file. Container authenticity comes from the cipher's tag.
- **Verification is not a trust decision.** A passed round trip proves internal
  consistency for the selected operation, not that the data is trustworthy.
- **Encryption is not execution safety.** Never run transformed data because it
  is encrypted, encoded, or has a familiar file extension.

---

## 8. Operational guidance

Recommended:

1. Prefer `aes-256-gcm` (default) or `chacha20-poly1305`.
2. Use a password manager or a random 32-byte key; avoid short or reused
   passwords.
3. Read passwords from stdin or a protected file, not `--password`.
4. Keep key files separate from ciphertext and restrict directory permissions.
5. Store a trusted SHA-256 of important outputs if you need accidental-change
   detection.
6. Decrypt to a new path and verify with `byteforge verify`.
7. Use `--no-color`, `--no-banner`, and `--no-verify` only when appropriate for
   automation; do not disable verification to "make it work".
8. Treat `--verbose` output as sensitive.
9. Use `--allow-legacy` only for a specific interoperability need.
10. Keep the Go toolchain and `golang.org/x/crypto` updated, and rebuild from
    reviewed source.

Avoid:

- reusing `--nonce` with the same key;
- using XOR, RC4, CBC, or CTR as a default for new sensitive data;
- placing keys next to ciphertext "for convenience";
- assuming file deletion erases data;
- publishing containers, keys, passwords, or verbose logs together;
- treating a successful decode as a malware verdict.

---

## 9. Dependency and build integrity

ByteForge uses the Go standard library and one direct external dependency,
`golang.org/x/crypto`, for scrypt and ChaCha20-Poly1305. `go.sum` pins module
content hashes. Release builds should use `-trimpath`, record the Go version
and VCS revision (`byteforge version --verbose`), and be built from a reviewed
commit.

The project does not implement cryptographic primitives from scratch. If a
maintained implementation is unavailable for a desired algorithm, the correct
response is to omit the algorithm, not to write a custom primitive.

---

## 10. Reporting a vulnerability

Do not open a public issue containing an exploit, key material, or sensitive
payloads. Report suspected vulnerabilities privately to the project maintainer
through the repository's private security advisory channel, with:

- affected version and platform;
- a minimal reproduction that does not include real secrets;
- expected and observed behavior;
- impact assessment and any suggested fix.

There is no guaranteed response time or bug-bounty program. Until a fix is
available, avoid using the affected feature for sensitive data.

---

## 11. Security checklist

Before relying on ByteForge for sensitive data:

- [ ] The binary was built from reviewed source with a supported Go toolchain.
- [ ] The cipher is an authenticated default, not XOR, RC4, or bare CBC/CTR.
- [ ] The password or key has adequate entropy and is unique to this use.
- [ ] The password was supplied through stdin or a protected file.
- [ ] The key file is stored separately with restrictive permissions.
- [ ] The output path is trusted and not silently overwritten.
- [ ] The container and key are backed up according to your recovery plan.
- [ ] `byteforge verify` succeeds after decryption.
- [ ] No secrets appear in shell history, process listings, terminal logs, or
      CI artifacts.
- [ ] You have not executed, loaded, or injected the transformed data.
