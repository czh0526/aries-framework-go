package did

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/multiformats/go-multibase"
)

type VerificationMethod struct {
	ID                string
	Type              string
	Controller        string
	Value             []byte
	jsonWebKey        *jwk.JWK
	relativeURL       bool
	multibaseEncoding multibase.Encoding
}

func (vm *VerificationMethod) JSONWebKey() *jwk.JWK {
	return vm.jsonWebKey
}
