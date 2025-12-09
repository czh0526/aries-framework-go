package jwt

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	sigverifier "github.com/czh0526/aries-framework-go/component/models/signature/verifier"
)

type KeyResolver interface {
	Resolve(shat, kid string) (*sigapi.PublicKey, error)
}

type BasicVerifier struct {
	resolver          KeyResolver
	compositeVerifier *jose.CompositeAlgSigVerifier
}

func (v BasicVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return v.compositeVerifier.Verify(joseHeaders, payload, signingInput, signature)
}

var _ jose.SignatureVerifier = (*BasicVerifier)(nil)

func NewVerifier(resolver KeyResolver) *BasicVerifier {
	verifiers := []sigverifier.SignatureVerifier{
		sigverifier.NewECDSAES256SignatureVerifier(),
	}
}
