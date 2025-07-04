package local

import (
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	cipherutil "github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/local/internal/cipher"
	"github.com/czh0526/aries-framework-go/component/log"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"io"
)

var logger = log.New("aries-framework/lock")

const masterKeyLen = 512

func NewService(masterKeyReader io.Reader, secLock spisecretlock.Service) (spisecretlock.Service, error) {
	masterKeyData := make([]byte, masterKeyLen)

	if masterKeyReader == nil {
		return nil, fmt.Errorf("masterKeyReader is nul")
	}

	n, err := masterKeyReader.Read(masterKeyData)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}
	}
	if n == 0 {
		return nil, fmt.Errorf("masterKeyReader is empty")
	}

	var masterKey []byte
	if secLock != nil {
		decResponse, e := secLock.Decrypt("", &spisecretlock.DecryptRequest{
			Ciphertext: string(masterKeyData[:n]),
		})
		if e != nil {
			return nil, e
		}
		masterKey = []byte(decResponse.Plaintext)

	} else {
		masterKey, err = base64.URLEncoding.DecodeString(string(masterKeyData[:n]))
		if err != nil {
			masterKey = make([]byte, n)
			copy(masterKey, masterKeyData)
		}
	}

	aead, err := cipherutil.CreateAESCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return &Lock{
		aead: aead,
	}, nil
}

type Lock struct {
	aead cipher.AEAD
}

func (l *Lock) Encrypt(keyURI string, req *spisecretlock.EncryptRequest) (*spisecretlock.EncryptResponse, error) {
	nonce := random.GetRandomBytes(uint32(l.aead.NonceSize()))
	ct := l.aead.Seal(nil, nonce, []byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	ct = append(nonce, ct...)

	return &spisecretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

func (l *Lock) Decrypt(keyURI string, req *spisecretlock.DecryptRequest) (*spisecretlock.DecryptResponse, error) {
	ct, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := uint32(l.aead.NonceSize())
	if len(ct) <= int(nonceSize) {
		return nil, fmt.Errorf("invalid request")
	}

	nonce := ct[:nonceSize]
	ct = ct[nonceSize:]

	pt, err := l.aead.Open(nil, nonce, ct, []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, err
	}

	return &spisecretlock.DecryptResponse{
		Plaintext: string(pt),
	}, nil
}
