package ecdh

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func NewECDHEncrypt(kh *keyset.Handle) (api.CompositeEncrypt, error) {
	return NewECDHEncryptWithKeyManager(kh, nil)
}

func NewECDHEncryptWithKeyManager(kh *keyset.Handle, km registry.KeyManager) (api.CompositeEncrypt, error) {
	ps, err := kh.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("ecdh_factory: cannot botain primitive set: %w", err)
	}

	return newEncryptPrimitiveSet(ps)
}
