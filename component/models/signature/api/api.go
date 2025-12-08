package api

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/models/ld/processor"
)

type SignatureSuite interface {
	GetCanonicalDocument(doc map[string]interface{}, opts ...processor.Opts) ([]byte, error)

	GetDigest(doc []byte) []byte

	Verify(pubKey *PublicKey, doc []byte, signature []byte) error

	Accept(signatureType string) bool

	CompactProof() bool
}

type PublicKey struct {
	Type  string
	Value []byte
	JWK   *jwk.JWK
}
