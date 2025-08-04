package ecdh

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func NewECDHCrypto(kh *keyset.Handle) (tink.AEAD, error) {
	return NewECDHDecryptWithKeyManager(kh, nil)
}

func NewECDHDecryptWithKeyManager(kh *keyset.Handle, km *keyset.Handle) (tink.AEAD, error) {
	return &compositeCrypto{
		kh: kh,
	}, nil
}

type compositeCrypto struct {
	kh *keyset.Handle
}

func (e *compositeCrypto) Encrypt(plaintext, aad []byte) ([]byte, error) {
	encrypter, err := aead.New(e.kh)
	if err != nil {
		return nil, fmt.Errorf("compositeCrypto: cannot obtain encrypter: %s", err)
	}

	return encrypter.Encrypt(plaintext, aad)
}

func (d *compositeCrypto) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	decrypter, err := aead.New(d.kh)
	if err != nil {
		return nil, fmt.Errorf("compositeCrypto: cannot obtain decrypter: %s", err)
	}

	return decrypter.Decrypt(ciphertext, aad)
}

var _ tink.AEAD = (*compositeCrypto)(nil)
