package ecdh

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/internal/internalapi"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func NewECDHDecrypt(kh *keyset.Handle) (api.CompositeDecrypt, error) {
	return NewECDHDecryptWithKeyManager(kh, nil)
}

func NewECDHDecryptWithKeyManager(kh *keyset.Handle, km *keyset.Handle) (api.CompositeDecrypt, error) {
	ps, err := keyset.Primitives[tink.AEAD](kh, internalapi.Token{})
	return &compositeDecrypt{
		kh: kh,
	}, nil
}

type compositeDecrypt struct {
	kh *keyset.Handle
}

func (d *compositeDecrypt) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	decrypter, err := aead.New(d.kh)
	if err != nil {
		return nil, fmt.Errorf("compositeDecrypt: cannot obtain decrypter: %s", err)
	}

	return decrypter.Encrypt(ciphertext, aad)
}

var _ api.CompositeDecrypt = (*compositeDecrypt)(nil)
