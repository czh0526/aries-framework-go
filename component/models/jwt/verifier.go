package jwt

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	signatureapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
)

type KeyResolver interface {
	Resolve(shat, kid string) (*signatureapi.PublicKey, error)
}

type BaseVerifier struct {
	resolver          KeyResolver
	compositeVerifier *jose.CompositeAlgSigVerifier
}

func NewVerifier(resolver KeyResolver) *BasicVerifier {

}
