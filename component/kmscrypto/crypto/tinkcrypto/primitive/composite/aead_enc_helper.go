package composite

import "github.com/tink-crypto/tink-go/v2/tink"

type EncrypterHelper interface {
	GetAEAD(symmetricHeyValue []byte) (tink.AEAD, error)

	GetTagSize() int

	GetIVSize() int

	BuildEncData(ct []byte) ([]byte, error)

	BuildDecData(encData *EncryptedData) []byte
}
