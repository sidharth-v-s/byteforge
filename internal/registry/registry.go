// Package registry defines the stable metadata and interface contracts shared
// by ByteForge's codec, cipher, and renderer registries.
//
// The contracts deliberately do not force every cipher into the same
// parameter assumptions. Encoders are byte-to-byte, ciphers expose explicit
// key/nonce/tag sizes plus authenticated encryption and decryption, and
// renderers receive non-secret metadata alongside the transformed bytes.
package registry

// Security classifications used by `byteforge formats` and documentation.
const (
	SecurityRepresentation = "representation"
	SecurityTransform      = "transform"
	SecurityAuthenticated  = "authenticated"
	SecurityCompatibility  = "compatibility"
	SecurityLegacy         = "legacy"
	SecurityRenderer       = "renderer"
)

// Info describes a registered component. It is intentionally non-secret and
// JSON-friendly so `byteforge formats --json` can be machine-consumed.
type Info struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Security    string   `json:"security"`
	Reversible  bool     `json:"reversible"`
	Input       string   `json:"input,omitempty"`
	Output      string   `json:"output,omitempty"`
	Parameters  []string `json:"parameters,omitempty"`
	Warning     string   `json:"warning,omitempty"`
}

// Codec is a reversible representation conversion. Encode and Decode operate
// on bytes; text codecs return text encoded as bytes.
type Codec interface {
	Info() Info
	Encode(data []byte) ([]byte, error)
	Decode(data []byte) ([]byte, error)
}

// Cipher is an encryption algorithm adapter. Implementations validate key and
// nonce sizes, compute the exact ciphertext length up front (so container
// headers can be authenticated), and return the authentication tag separately
// when the underlying construction provides one.
//
// AAD is authenticated but never encrypted. Decrypt must verify authentication
// before returning any plaintext.
type Cipher interface {
	Info() Info
	KeySize() int
	NonceSize() int
	TagSize() int
	// CiphertextLen returns the exact ciphertext length for plaintextLen.
	CiphertextLen(plaintextLen int) int
	Encrypt(key, nonce, plaintext, aad []byte) (ciphertext, tag []byte, err error)
	Decrypt(key, nonce, ciphertext, tag, aad []byte) (plaintext []byte, err error)
}

// Renderer formats transformed bytes. Renderers are independent of the codec
// or cipher that produced the bytes.
type Renderer interface {
	Info() Info
	Render(data []byte, meta Meta) ([]byte, error)
}

// Meta carries non-secret context from the operation coordinator to renderers.
type Meta struct {
	Tool         string
	Version      string
	Operation    string
	Format       string
	Encoding     string
	Cipher       string
	InputSize    int
	InputSHA256  string
	Verification string
	Timestamp    string
	Symbol       string
	BytesPerLine int
}

// Transform is a reversible, non-cryptographic byte transformation
// (currently XOR variants). The same Apply operation reverses it.
type Transform interface {
	Info() Info
	ValidateKey(key []byte) error
	Apply(data, key []byte) ([]byte, error)
}
