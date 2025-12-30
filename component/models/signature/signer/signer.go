package signer

import ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"

type SignatureSuite interface {
	GetCanonicalDocument(doc map[string]interface{}, opts ...ldprocessormodel.Opts) ([]byte, error)

	GetDigest(doc []byte) []byte

	Accept(signatureType string) bool

	Sign(doc []byte) ([]byte, error)

	Alg() string

	CompactProof() bool
}
