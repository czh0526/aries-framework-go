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
	return &compositeEncrypt{
		kh: kh,
	}, nil
}

type compositeEncrypt struct {
	kh *keyset.Handle
}

func (e *compositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
	encrypter, err := aead.New(e.kh)
	if err != nil {
		return nil, fmt.Errorf("compositeEncrypt: cannot obtain encrypter: %s", err)
	}

	return encrypter.Encrypt(plaintext, aad)
}

var _ api.CompositeEncrypt = (*compositeEncrypt)(nil)
