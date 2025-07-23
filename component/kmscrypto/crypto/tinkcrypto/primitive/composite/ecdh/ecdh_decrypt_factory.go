package ecdh

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

func NewECDHDecrypt(kh *keyset.Handle) (api.CompositeDecrypt, error) {
	return NewECDHDecryptWithKeyManager(kh, nil)
}

func NewECDHDecryptWithKeyManager(kh *keyset.Handle, km *keyset.Handle) (api.CompositeDecrypt, error) {
	return aead.New(kh)
}
