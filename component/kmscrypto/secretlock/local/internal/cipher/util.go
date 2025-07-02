package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

func CreateAESCipher(masterKey []byte) (cipher.AEAD, error) {
	cipherBlock, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(cipherBlock)
}
