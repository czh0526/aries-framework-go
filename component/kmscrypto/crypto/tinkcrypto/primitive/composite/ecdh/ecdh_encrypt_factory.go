package ecdh

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func NewECDHEncrypt(kh *keyset.Handle) (api.CompositeEncrypt, error) {
	return NewECDHEncryptWithKeyManager(kh, nil)
}

func NewECDHEncryptWithKeyManager(kh *keyset.Handle, km registry.KeyManager) (api.CompositeEncrypt, error) {
	return aead.New(kh)
}

type encryptPrimitiveSet struct {
}

func (e encryptPrimitiveSet) Encrypt(plaintext, aad []byte) ([]byte, error) {
	return nil, fmt.Errorf("ecdh_encrypt_factory: not yet implemented")
}

var _ api.CompositeEncrypt = (*encryptPrimitiveSet)(nil)
