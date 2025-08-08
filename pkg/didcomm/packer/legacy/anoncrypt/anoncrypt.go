package anoncrypt

import (
	"crypto/rand"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"io"
)

type Packer struct {
	randSource io.Reader
	kms        spikms.KeyManager
}

const encodingType string = "JWM/1.0"

const anonCrypt string = "Anoncrypt"

const anonCryptEncType string = "chacha20poly1305_ietf"

func New(ctx packer.Provider) *Packer {
	k := ctx.KMS()

	return &Packer{
		randSource: rand.Reader,
		kms:        k,
	}
}

func (p *Packer) EncodingType() string {
	return encodingType
}

type legacyEnvelope struct {
	Protected  string `json:"protected,omitempty"`
	IV         string `json:"iv,omitempty"`
	CipherText string `json:"ciphertext,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

type protected struct {
	Enc        string      `json:"enc,omitempty"`
	Typ        string      `json:"typ,omitempty"`
	Alg        string      `json:"alg,omitempty"`
	Recipients []recipient `json:"recipients,omitempty"`
}

type recipientHeader struct {
	KID string `json:"kid,omitempty"`
}

type recipient struct {
	EncryptedKey string          `json:"encrypted_key,omitempty"`
	Header       recipientHeader `json:"header,omitempty"`
}

func newCryptoBox(km spikms.KeyManager) (kms.CryptoBox, error) {
	switch km.(type) {
	case *localkms.LocalKMS:
		return localkms.NewCryptoBox(km)
	default:
		return localkms.NewCryptoBox(km)
	}
}
