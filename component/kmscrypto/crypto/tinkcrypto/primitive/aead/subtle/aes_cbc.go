package subtle

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

const (
	AESCBCIVSize = 16
)

type AESCBC struct {
	Key []byte
}

func (a *AESCBC) Encrypt(plaintext []byte) ([]byte, error) {
	plainTextSize := len(plaintext)
	if plainTextSize > maxInt-AESCBCIVSize {
		return nil, errors.New("aes_cbc: plaintext too long")
	}

	iv := a.newIV()

	cbc, err := newCipher(a.Key, iv, false)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc: Encrypt() failed: %w", err)
	}

	ciphertext := make([]byte, AESCBCIVSize+plainTextSize)
	if n := copy(ciphertext, iv); n != AESCBCIVSize {
		return nil, fmt.Errorf("aes_cbc: failed to copy IV (copied %d|%d bytes)", n, AESCBCIVSize)
	}

	if n := copy(ciphertext[AESCBCIVSize:], plaintext); n != plainTextSize {
		return nil, fmt.Errorf("aes_cbc: failed to copy plaintext (copied %d|%d bytes)", n, plainTextSize)
	}

	ciphertext = Pad(ciphertext, plainTextSize, cbc.BlockSize())
	cbc.CryptBlocks(ciphertext[AESCBCIVSize:], ciphertext[AESCBCIVSize:])
	return ciphertext, nil
}

func (a *AESCBC) Decrypt(ciphertext []byte) ([]byte, error) {
	ciphertextSize := len(ciphertext)
	if ciphertextSize < AESCBCIVSize {
		return nil, errors.New("aes_cbc: ciphertext too short")
	}

	iv := ciphertext[:AESCBCIVSize]

	cbc, err := newCipher(a.Key, iv, true)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc: Decrypt() %w", err)
	}

	blockSize := cbc.BlockSize()

	if len(ciphertext[AESCBCIVSize:])%blockSize > 0 {
		return nil, errors.New("aes_cbc: invalid ciphertext padding")
	}

	plaintext := make([]byte, ciphertextSize-AESCBCIVSize)
	cbc.CryptBlocks(plaintext, ciphertext[AESCBCIVSize:])

	if len(plaintext) == 0 {
		return plaintext, nil
	}

	return Unpad(plaintext), nil
}

func (a *AESCBC) newIV() []byte {
	return random.GetRandomBytes(uint32(AESCBCIVSize))
}

func newCipher(key []byte, iv []byte, decrypt bool) (cipher.BlockMode, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc: failed to create block cipher, error: %w", err)
	}

	if len(iv) < aes.BlockSize {
		return nil, errors.New("aes_cbc: invalid iv size")
	}

	if decrypt {
		return cipher.NewCBCDecrypter(block, iv), nil
	}

	return cipher.NewCBCEncrypter(block, iv), nil
}

func NewAESCBC(key []byte) (*AESCBC, error) {
	keySize := uint32(len(key))
	if err := ValidateAESKeySize(keySize); err != nil {
		return nil, fmt.Errorf("aes_cbc: NewAESCBC() failed, err = %w", err)
	}

	return &AESCBC{Key: key}, nil
}

func Pad(text []byte, originalTextSize, blockSize int) []byte {
	// pad to block size if needed. The value of missing is between 0 and blockSize.
	missing := blockSize - (originalTextSize % blockSize)
	if missing > 0 {
		text = append(text, bytes.Repeat([]byte{byte(missing)}, missing)...)

		return text
	}

	// return original text if missing =< 0
	return text
}

// Unpad a padded text of blockSize.
func Unpad(text []byte) []byte {
	last := text[len(text)-1]
	count := int(last)

	// check for padding, count is the padding value.
	if count > 0 {
		padding := bytes.Repeat([]byte{last}, count)
		if bytes.HasSuffix(text, padding) {
			// padding was found, trim it and return remaining plaintext.
			return text[:len(text)-len(padding)]
		}
	}

	// count is <= 0 or text has no padding, return text as is.
	return text
}
