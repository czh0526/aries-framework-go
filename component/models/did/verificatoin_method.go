package did

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/multiformats/go-multibase"
	"strings"
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

func NewVerificationMethodFromJWK(id, keyType, controller string, j *jwk.JWK) (*VerificationMethod, error) {
	pkBytes, err := j.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("convert JWK to public key bytes failed, err = %w", err)
	}

	relativeURL := false
	if strings.HasPrefix(id, "#") {
		relativeURL = true
	}

	return &VerificationMethod{
		ID:          id,
		Type:        keyType,
		Controller:  controller,
		Value:       pkBytes,
		jsonWebKey:  j,
		relativeURL: relativeURL,
	}, nil
}
