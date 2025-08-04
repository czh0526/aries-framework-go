package authcrypt

import (
	"crypto/rand"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"io"
)

type Packer struct {
	randSource io.Reader
	kms        spikms.KeyManager
}

const encodingType = "JWM/1.0"

func (p *Packer) EncodingType() string {
	return encodingType
}

func New(ctx packer.Provider) *Packer {
	k := ctx.KMS()

	return &Packer{
		randSource: rand.Reader,
		kms:        k,
	}
}

type protected struct {
	Enc        string `json:"enc,omitempty"`
	Typ        string `json:"typ,omitempty"`
	Alg        string `json:"alg,omitempty"`
	Recipients string `json:"recipients,omitempty"`
}

type recipient struct {
	EncryptedKey string          `json:"encrypted_key,omitempty"`
	Header       recipientHeader `json:"header,omitempty"`
}

type recipientHeader struct {
	KID    string `json:"kid,omitempty"`
	Sender string `json:"sender,omitempty"`
	IV     string `json:"iv,omitempty"`
}
