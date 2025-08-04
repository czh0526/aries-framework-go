package subtle

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
)

type ECDHAEADCompositeCrypto struct {
	encHelper composite.EncrypterHelper
	cek       []byte
}

func NewECDHAEADCompositeCrypto(encHelper composite.EncrypterHelper, cek []byte) *ECDHAEADCompositeCrypto {
	return &ECDHAEADCompositeCrypto{
		encHelper: encHelper,
		cek:       cek,
	}
}

func (e *ECDHAEADCompositeCrypto) Encrypt(plaintext, aad []byte) ([]byte, error) {
	if e.cek == nil {
		return nil, fmt.Errorf("ecdhAEADCompositeEncrypt: missing cek")
	}

	aead, err := e.encHelper.GetAEAD(e.cek)
	if err != nil {
		return nil, err
	}

	ct, err := aead.Encrypt(plaintext, aad)
	if err != nil {
		return nil, err
	}

	return e.encHelper.BuildEncData(ct)
}

func (d *ECDHAEADCompositeCrypto) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	encData := new(composite.EncryptedData)

	err := json.Unmarshal(ciphertext, encData)
	if err != nil {
		return nil, err
	}

	if d.cek == nil {
		return nil, fmt.Errorf("ecdh decrypt: missing cek")
	}

	aead, err := d.encHelper.GetAEAD(d.cek)
	if err != nil {
		return nil, err
	}

	finalCT := d.encHelper.BuildDecData(encData)

	return aead.Decrypt(finalCT, aad)
}
