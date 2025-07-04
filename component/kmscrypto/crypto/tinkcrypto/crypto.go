package tinkcrypto

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"github.com/tink-crypto/tink-go/v2/internal/primitiveset"
	"github.com/tink-crypto/tink-go/v2/aead"
	aeadsubtle "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
)

var errBadKeyHandleFormat = errors.New("bad key handle format")

type Crypto struct {
}

func (c Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, nil, errBadKeyHandleFormat
	}

	ps, err := keyset.Primitives[]()
	if err != nil {
		return nil, nil, fmt.Errorf("get primary key: %w", err)
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, nil, fmt.Errorf("create new aead: %w", err)
	}

	ct, err := a.Encrypt(msg, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt msg: %w", err)
	}

	ivSize := nonceSize(ps)
	prefixLength := len(ps.Primary.Prefix)
	cipherText := ct[prefixLength+ivSize:]
	nonce := ct[prefixLength : prefixLength+ivSize]

	return cipherText, nonce, nil
}

func (c Crypto) Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c Crypto) Verify(signature, msg []byte, kh interface{}) error {
	//TODO implement me
	panic("implement me")
}

var _ spicrypto.Crypto = (*Crypto)(nil)

func New() (*Crypto, error) {
	log.Printf("【default】New tink crypto")
	return &Crypto{}, nil
}

func nonceSize(ps *primitiveset.PrimitiveSet[]) int {
	var ivSize int
	switch ps.{
	case *aeadsubtle.XChaCha20Poly1305:
		ivSize = chacha20poly1305.NonceSizeX
	case *aeadsubtle.AESGCM:
		ivSize = aeadsubtle.AESGCMIVSize
	case *aeadsubtle.EncryptThenAuthenticate:
		ivSize = subtle.AES128Size
	default:
		ivSize = aeadsubtle.AESGCMIVSize
	}
	return ivSize
}
