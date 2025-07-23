package subtle

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
)

type ECDHAEADCompositeDecrypt struct {
	encHelper composite.EncrypterHelper
	cek       []byte
}

func NewECDHAEADCompositeDecrypt(encHelper composite.EncrypterHelper, cek []byte) *ECDHAEADCompositeDecrypt {
	return &ECDHAEADCompositeDecrypt{
		encHelper: encHelper,
		cek:       cek,
	}
}

func (d *ECDHAEADCompositeDecrypt) Decrypt(ciphertext, aad []byte) ([]byte, error) {
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
