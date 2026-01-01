package suite

import (
	"errors"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmssigner"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
)

type signer interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

type verifier interface {
	Verify(pubKeyValue *sigapi.PublicKey, doc, signature []byte) error
}

var _ signer = (*kmssigner.KMSSigner)(nil)

var (
	ErrSignerNotDefined = errors.New("signer is not defined")

	ErrVerifierNotDefined = errors.New("verifier is not defined")
)

type SignatureSuite struct {
	Signer         signer
	Verifier       verifier
	CompactedProof bool
}

func (s *SignatureSuite) Sign(doc []byte) ([]byte, error) {
	if s.Signer == nil {
		return nil, ErrSignerNotDefined
	}

	return s.Signer.Sign(doc)
}

func (s *SignatureSuite) Verify(pubKeyValue *sigapi.PublicKey, doc, signature []byte) error {
	if s.Verifier == nil {
		return ErrVerifierNotDefined
	}

	return s.Verifier.Verify(pubKeyValue, doc, signature)
}

func (s *SignatureSuite) Alg() string {
	return s.Signer.Alg()
}

func (s *SignatureSuite) CompactProof() bool {
	return s.CompactedProof
}

type Opt func(opts *SignatureSuite)

func WithSigner(s signer) Opt {
	return func(opts *SignatureSuite) {
		opts.Signer = s
	}
}

func InitSuiteOptions(suite *SignatureSuite, opts ...Opt) *SignatureSuite {
	for _, opt := range opts {
		opt(suite)
	}

	return suite
}
