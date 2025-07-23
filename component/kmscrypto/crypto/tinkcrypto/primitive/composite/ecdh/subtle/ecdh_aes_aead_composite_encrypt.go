package subtle

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
)

type ECDHAEADCompositeEncrypt struct {
	encHelper composite.EncrypterHelper
	cek       []byte
}

func (e *ECDHAEADCompositeEncrypt) Encrypt(plaintext, aad []byte) ([]byte, error) {
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

var _ api.CompositeEncrypt = (*ECDHAEADCompositeEncrypt)(nil)

func NewECDHAEADCompositeEncrypt(encHelper composite.EncrypterHelper, cek []byte) api.CompositeEncrypt {
	return &ECDHAEADCompositeEncrypt{
		encHelper: encHelper,
		cek:       cek,
	}
}
