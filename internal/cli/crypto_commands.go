package cli

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zoro/byteforge/internal/bferrors"
	"github.com/zoro/byteforge/internal/bytesutil"
	"github.com/zoro/byteforge/internal/container"
	"github.com/zoro/byteforge/internal/cryptography"
	"github.com/zoro/byteforge/internal/fsutil"
	"github.com/zoro/byteforge/internal/input"
	"github.com/zoro/byteforge/internal/registry"
	"github.com/zoro/byteforge/internal/renderer"
	"github.com/zoro/byteforge/internal/reporting"
)

type keyFlags struct {
	hexKey        string
	keyFile       string
	password      string
	passwordFile  string
	passwordStdin bool
}

func (a *App) registerKeyFlags(fs *flag.FlagSet, k *keyFlags) {
	fs.StringVar(&k.hexKey, "key", "", "explicit key as hex")
	fs.StringVar(&k.keyFile, "key-file", "", "read explicit key as hex from FILE")
	fs.StringVar(&k.password, "password", "", "password (visible in the process list)")
	fs.StringVar(&k.passwordFile, "password-file", "", "read password from FILE")
	fs.BoolVar(&k.passwordStdin, "password-stdin", false, "read password from stdin")
}

func (k *keyFlags) counts() (passwordSources, keySources int) {
	if k.password != "" {
		passwordSources++
	}
	if k.passwordFile != "" {
		passwordSources++
	}
	if k.passwordStdin {
		passwordSources++
	}
	if k.hexKey != "" {
		keySources++
	}
	if k.keyFile != "" {
		keySources++
	}
	return
}

func (k *keyFlags) validateCounts() error {
	pass, key := k.counts()
	if pass > 1 {
		return bferrors.New(bferrors.Usage, "provide only one password source (--password, --password-file, or --password-stdin)")
	}
	if key > 1 {
		return bferrors.New(bferrors.Usage, "--key and --key-file are mutually exclusive")
	}
	if pass > 0 && key > 0 {
		return bferrors.New(bferrors.Usage, "choose either a password source or an explicit key, not both")
	}
	return nil
}

func (a *App) readPassword(k *keyFlags) ([]byte, error) {
	pass, _ := k.counts()
	if pass != 1 {
		return nil, bferrors.New(bferrors.Usage, "provide exactly one password source (--password, --password-file, or --password-stdin)")
	}
	if k.password != "" {
		if k.password == "" {
			return nil, bferrors.New(bferrors.Usage, "password must not be empty")
		}
		a.rep.Warn("--password is visible in the process list on some systems; prefer --password-file or --password-stdin")
		return []byte(k.password), nil
	}
	if k.passwordFile != "" {
		data, err := input.ReadPath(k.passwordFile, 1<<20)
		if err != nil {
			return nil, err
		}
		pw := bytes.TrimRight(data, "\r\n")
		if len(pw) == 0 {
			return nil, bferrors.New(bferrors.Usage, "password file %s is empty", k.passwordFile)
		}
		return pw, nil
	}
	data, err := io.ReadAll(io.LimitReader(a.Stdin, 1<<20))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.IO, err, "reading password from stdin")
	}
	pw := bytes.TrimRight(data, "\r\n")
	if len(pw) == 0 {
		return nil, bferrors.New(bferrors.Usage, "password from stdin is empty")
	}
	return pw, nil
}

func (a *App) readExplicitKey(k *keyFlags) ([]byte, error) {
	_, keyCount := k.counts()
	if keyCount != 1 {
		return nil, bferrors.New(bferrors.Usage, "provide exactly one key source (--key or --key-file)")
	}
	if k.hexKey != "" {
		key, err := bytesutil.ParseHex(k.hexKey)
		if err != nil {
			return nil, bferrors.Wrap(bferrors.Usage, err, "invalid --key")
		}
		return key, nil
	}
	data, err := input.ReadPath(k.keyFile, 1<<20)
	if err != nil {
		return nil, err
	}
	key, err := bytesutil.ParseHex(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, bferrors.Wrap(bferrors.Usage, err, "invalid key in %s", k.keyFile)
	}
	return key, nil
}

func requireKeySize(c registry.Cipher, key []byte) error {
	if len(key) != c.KeySize() {
		return bferrors.New(bferrors.Usage,
			"%s requires a %d-byte key, got %d bytes", c.Info().Name, c.KeySize(), len(key))
	}
	return nil
}

// ---------------------------------------------------------------- encrypt

func (a *App) cmdEncrypt(args []string) error {
	var f struct {
		input       inputFlags
		render      renderFlags
		keys        keyFlags
		cipherName  string
		nonceHex    string
		aad         string
		exportKey   string
		keySymbol   string
		allowLegacy bool
		noVerify    bool
	}
	fs := a.newFlagSet("encrypt", encryptUsage)
	a.registerCommon(fs)
	a.registerInputFlags(fs, &f.input)
	fs.StringVar(&f.cipherName, "cipher", "aes-256-gcm", "cipher identifier")
	a.registerKeyFlags(fs, &f.keys)
	fs.StringVar(&f.nonceHex, "nonce", "", "explicit nonce/IV as hex (tests/interoperability only)")
	fs.StringVar(&f.aad, "aad", "", "additional authenticated data")
	fs.StringVar(&f.exportKey, "export-key", "", "export key material to FILE (contains a secret)")
	fs.StringVar(&f.keySymbol, "key-symbol", "key", "symbol name for the rendered key declaration")
	fs.BoolVar(&f.allowLegacy, "allow-legacy", false, "permit legacy algorithms")
	a.registerRenderFlags(fs, &f.render)
	fs.BoolVar(&f.noVerify, "no-verify", false, "skip internal decrypt verification")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	a.rep.Banner()

	c, ok := cryptography.Get(f.cipherName)
	if !ok {
		return unknownName("cipher", f.cipherName, cryptography.Names())
	}
	if c.Info().Security == registry.SecurityLegacy && !f.allowLegacy {
		return bferrors.New(bferrors.Usage,
			"cipher %s is legacy and disabled by default: %s (rerun with --allow-legacy if you accept the risk)",
			c.Info().Name, c.Info().Warning)
	}
	if c.Info().Security == registry.SecurityLegacy {
		a.rep.Warn("%s: %s", c.Info().Name, c.Info().Warning)
	}
	if err := f.keys.validateCounts(); err != nil {
		return err
	}
	if err := validateRender(&f.render); err != nil {
		return err
	}
	keyCapable := renderer.KeyCapable(f.render.name)
	if keyCapable {
		if f.keySymbol == "" {
			return bferrors.New(bferrors.Usage, "--key-symbol must not be empty")
		}
		if f.keySymbol == f.render.symbol {
			return bferrors.New(bferrors.Usage, "--key-symbol must differ from --symbol")
		}
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}
	if f.exportKey != "" {
		if f.exportKey == a.common.Output {
			return bferrors.New(bferrors.Usage, "--export-key must not be the same path as --output")
		}
		if err := a.prepareKeyExport(f.exportKey); err != nil {
			return err
		}
	}
	src, err := a.loadInput(&f.input)
	if err != nil {
		return err
	}
	a.rep.Info("loaded %d bytes from %s", len(src.Data), src.Label)

	plaintext, padResult, err := a.applyPadding(src.Data, &f.render, "")
	if err != nil {
		return err
	}

	passSources, keySources := f.keys.counts()
	if passSources > 0 && keySources > 0 {
		return bferrors.New(bferrors.Usage, "choose either a password source or an explicit key, not both")
	}
	if passSources > 0 && f.exportKey != "" {
		return bferrors.New(bferrors.Usage, "--export-key is not applicable to password-based encryption; the derived key is included automatically for key-capable renderers")
	}

	var key []byte
	var salt []byte
	kdfID := cryptography.KDFNone
	keySource := ""
	generated := false
	switch {
	case passSources == 1:
		password, err := a.readPassword(&f.keys)
		if err != nil {
			return err
		}
		salt, err = cryptography.NewSalt()
		if err != nil {
			return err
		}
		key, err = cryptography.DeriveKeySize(password, salt, c.KeySize())
		if err != nil {
			return err
		}
		kdfID = cryptography.KDFScryptSHA256
		keySource = "password (scrypt)"
	case keySources == 1:
		key, err = a.readExplicitKey(&f.keys)
		if err != nil {
			return err
		}
		if err := requireKeySize(c, key); err != nil {
			return err
		}
		keySource = "explicit key"
	default:
		if f.exportKey == "" && !keyCapable {
			return bferrors.New(bferrors.Usage,
				"no key source: provide --password, --password-file, --password-stdin, --key, or --key-file; "+
					"to generate a random key with a raw/hex/base64 renderer you must also pass --export-key FILE")
		}
		key, err = cryptography.RandomBytes(c.KeySize())
		if err != nil {
			return err
		}
		generated = true
		keySource = "generated random key"
	}

	var nonce []byte
	if f.nonceHex != "" {
		nonce, err = bytesutil.ParseHex(f.nonceHex)
		if err != nil {
			return bferrors.Wrap(bferrors.Usage, err, "invalid --nonce")
		}
		if len(nonce) != c.NonceSize() {
			return bferrors.New(bferrors.Usage, "%s requires a %d-byte nonce, got %d bytes", c.Info().Name, c.NonceSize(), len(nonce))
		}
		a.rep.Warn("using an explicit nonce; never reuse a nonce with the same key")
	} else {
		nonce, err = cryptography.RandomBytes(c.NonceSize())
		if err != nil {
			return err
		}
	}

	cipherID, ok := cryptography.ID(c.Info().Name)
	if !ok {
		return bferrors.New(bferrors.Processing, "internal error: cipher %s has no container id", c.Info().Name)
	}
	h, err := container.NewHeader(cipherID, kdfID, salt, nonce, c.CiphertextLen(len(plaintext)), c.TagSize())
	if err != nil {
		return err
	}
	aad := h.AAD([]byte(f.aad))
	ct, tag, err := c.Encrypt(key, nonce, plaintext, aad)
	if err != nil {
		return err
	}
	blob, err := h.Encode(ct, tag)
	if err != nil {
		return err
	}

	verification := "SKIPPED"
	if !f.noVerify {
		got, vErr := c.Decrypt(key, nonce, ct, tag, aad)
		if vErr != nil {
			return bferrors.Wrap(bferrors.Verification, vErr, "internal decrypt verification failed")
		}
		if !bytes.Equal(got, plaintext) {
			return bferrors.New(bferrors.Verification, "internal decrypt verification failed: plaintext differs")
		}
		verification = "PASSED"
	}

	if f.exportKey != "" {
		if err := fsutil.WriteFile(f.exportKey, []byte(hex.EncodeToString(key)+"\n"), a.common.Force); err != nil {
			return err
		}
		a.rep.Warn("exported key material to %s — this file contains a secret", f.exportKey)
		a.rep.Warn("deleting a key file does not guarantee secure erasure from storage, backups, or memory")
	}

	meta := a.meta("encrypt", c.Info().Name, "", c.Info().Name, verification, plaintext, &f.render)
	var out []byte
	if keyCapable {
		out, err = renderer.RenderWithKey(f.render.name, blob, key, meta, f.keySymbol)
	} else {
		rend, _ := renderer.Get(f.render.name)
		out, err = rend.Render(blob, meta)
	}
	if err != nil {
		return err
	}
	if keyCapable {
		a.rep.Warn("key material is embedded in the output; treat the output as a secret and do not commit or share it")
	}
	path, err := a.emit(out, f.render.name)
	if err != nil {
		return err
	}

	a.verboseDetails("Plaintext", plaintext, nil)
	a.verboseDetails("Container", blob, nil)
	a.rep.Debug("nonce (not secret, unique per encryption): %s", hex.EncodeToString(nonce))
	if generated {
		if keyCapable {
			a.rep.Debug("generated a random %d-byte key; it is included in the output", len(key))
		} else {
			a.rep.Debug("generated a random %d-byte key; it was not printed", len(key))
		}
	}

	fields := []reporting.Field{
		{Key: "Operation", Value: "encrypt"},
		{Key: "Cipher", Value: c.Info().Name},
		{Key: "KDF", Value: cryptography.KDFName(kdfID)},
		{Key: "Key source", Value: keySource},
		{Key: "Container", Value: fmt.Sprintf("BFRG v%d", container.Version)},
		{Key: "Input size", Value: fmt.Sprintf("%d bytes", len(src.Data))},
		{Key: "Container size", Value: fmt.Sprintf("%d bytes", len(blob))},
		{Key: "Output size", Value: fmt.Sprintf("%d bytes", len(out))},
		{Key: "Size delta", Value: delta(len(plaintext), len(blob))},
		{Key: "Input SHA-256", Value: sha256Hex(src.Data)},
		{Key: "Container SHA-256", Value: sha256Hex(blob)},
		{Key: "Output SHA-256", Value: sha256Hex(out)},
		{Key: "Verification", Value: verification},
		{Key: "Output file", Value: path},
	}
	fields = append(fields, paddingFields(padResult)...)
	if keyCapable {
		fields = append(fields, reporting.Field{Key: "Key material", Value: fmt.Sprintf("included in output (%d bytes)", len(key))})
	}
	a.summary(fields)
	return nil
}

func (a *App) prepareKeyExport(path string) error {
	if !a.common.Force && fsutil.Exists(path) {
		return bferrors.New(bferrors.IO, "key export file already exists: %s (use --force to overwrite)", path)
	}
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return bferrors.New(bferrors.IO, "key export directory does not exist: %s", dir)
		}
		return bferrors.Wrap(bferrors.IO, err, "cannot access key export directory %s", dir)
	}
	return nil
}

// ---------------------------------------------------------------- decrypt

func (a *App) cmdDecrypt(args []string) error {
	var f struct {
		input       inputFlags
		render      renderFlags
		keys        keyFlags
		aad         string
		allowLegacy bool
		noVerify    bool
	}
	fs := a.newFlagSet("decrypt", decryptUsage)
	a.registerCommon(fs)
	a.registerInputFlags(fs, &f.input)
	a.registerKeyFlags(fs, &f.keys)
	fs.StringVar(&f.aad, "aad", "", "additional authenticated data used at encryption")
	fs.BoolVar(&f.allowLegacy, "allow-legacy", false, "permit legacy algorithms")
	a.registerRenderFlags(fs, &f.render)
	fs.BoolVar(&f.noVerify, "no-verify", false, "skip re-encryption verification")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	a.rep.Banner()

	if err := f.keys.validateCounts(); err != nil {
		return err
	}
	if err := validateRender(&f.render); err != nil {
		return err
	}
	if err := a.prepareOutput(); err != nil {
		return err
	}
	src, err := a.loadInput(&f.input)
	if err != nil {
		return err
	}

	parsed, err := container.Parse(src.Data, int(a.common.MaxInput))
	if err != nil {
		return err
	}
	c, ok := cryptography.ByID(parsed.Header.CipherID)
	if !ok {
		return bferrors.New(bferrors.Usage, "container uses unsupported cipher id %d", parsed.Header.CipherID)
	}
	if c.Info().Security == registry.SecurityLegacy && !f.allowLegacy {
		return bferrors.New(bferrors.Usage,
			"container uses legacy cipher %s, disabled by default (rerun with --allow-legacy if you accept the risk)",
			c.Info().Name)
	}
	if c.Info().Security == registry.SecurityLegacy {
		a.rep.Warn("%s: %s", c.Info().Name, c.Info().Warning)
	}

	passSources, keySources := f.keys.counts()
	var key []byte
	switch parsed.Header.KDFID {
	case cryptography.KDFNone:
		if passSources > 0 {
			return bferrors.New(bferrors.Usage,
				"container is not password-protected; provide --key HEX or --key-file FILE")
		}
		if keySources != 1 {
			return bferrors.New(bferrors.Usage,
				"container is not password-protected; provide --key HEX or --key-file FILE")
		}
		key, err = a.readExplicitKey(&f.keys)
		if err != nil {
			return err
		}
		if err := requireKeySize(c, key); err != nil {
			return err
		}
	case cryptography.KDFScryptSHA256:
		if keySources > 0 {
			return bferrors.New(bferrors.Usage,
				"container is password-protected; provide --password, --password-file, or --password-stdin (not an explicit key)")
		}
		if passSources != 1 {
			return bferrors.New(bferrors.Usage,
				"container is password-protected; provide --password, --password-file, or --password-stdin")
		}
		password, err := a.readPassword(&f.keys)
		if err != nil {
			return err
		}
		key, err = cryptography.DeriveKeySize(password, parsed.Header.Salt, c.KeySize())
		if err != nil {
			return err
		}
	default:
		return bferrors.New(bferrors.Usage,
			"container uses unsupported KDF id %d (this build supports none and scrypt-sha256)", parsed.Header.KDFID)
	}

	aad := parsed.AAD([]byte(f.aad))
	plain, err := c.Decrypt(key, parsed.Header.Nonce, parsed.Ciphertext, parsed.Tag, aad)
	if err != nil {
		// Do not write anything on authentication failure.
		return bferrors.Wrap(bferrors.Verification, err, "decryption failed")
	}

	verification := "SKIPPED"
	if !f.noVerify {
		ct2, tag2, vErr := c.Encrypt(key, parsed.Header.Nonce, plain, aad)
		if vErr != nil {
			return bferrors.Wrap(bferrors.Verification, vErr, "re-encryption verification failed")
		}
		if !bytes.Equal(ct2, parsed.Ciphertext) || !bytes.Equal(tag2, parsed.Tag) {
			return bferrors.New(bferrors.Verification, "re-encryption verification failed: ciphertext differs")
		}
		verification = "PASSED"
	}

	plain, padResult, err := a.applyPadding(plain, &f.render, "")
	if err != nil {
		return err
	}

	rend, _ := renderer.Get(f.render.name)
	out, err := rend.Render(plain, a.meta("decrypt", c.Info().Name, "", c.Info().Name, verification, src.Data, &f.render))
	if err != nil {
		return err
	}
	path, err := a.emit(out, f.render.name)
	if err != nil {
		return err
	}

	a.verboseDetails("Container", src.Data, nil)
	a.verboseDetails("Plaintext", plain, nil)

	fields := []reporting.Field{
		{Key: "Operation", Value: "decrypt"},
		{Key: "Cipher", Value: c.Info().Name},
		{Key: "KDF", Value: cryptography.KDFName(parsed.Header.KDFID)},
		{Key: "Container", Value: fmt.Sprintf("BFRG v%d", parsed.Header.Version)},
		{Key: "Input size", Value: fmt.Sprintf("%d bytes", len(src.Data))},
		{Key: "Plaintext size", Value: fmt.Sprintf("%d bytes", len(plain))},
		{Key: "Output size", Value: fmt.Sprintf("%d bytes", len(out))},
		{Key: "Size delta", Value: delta(len(src.Data), len(out))},
		{Key: "Input SHA-256", Value: sha256Hex(src.Data)},
		{Key: "Plaintext SHA-256", Value: sha256Hex(plain)},
		{Key: "Output SHA-256", Value: sha256Hex(out)},
		{Key: "Verification", Value: verification},
		{Key: "Output file", Value: path},
	}
	fields = append(fields, paddingFields(padResult)...)
	a.summary(fields)
	return nil
}
