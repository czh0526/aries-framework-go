package hkdf

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	cipherutil "github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/local/internal/cipher"
	"github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
)

type masterLockHKDF struct {
	h    func() hash.Hash
	salt []byte
	aead cipher.AEAD
}

func (m masterLockHKDF) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	nonce := random.GetRandomBytes(uint32(m.aead.NonceSize()))
	ct := m.aead.Seal(nil, nonce, []byte(req.Plaintext), []byte(req.AdditionalAuthenticatedData))
	ct = append(nonce, ct...)

	return &secretlock.EncryptResponse{
		Ciphertext: base64.URLEncoding.EncodeToString(ct),
	}, nil
}

func (m masterLockHKDF) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	ct, err := base64.URLEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return nil, err
	}

	nonceSize := uint32(m.aead.NonceSize())
	if len(ct) <= int(nonceSize) {
		return nil, fmt.Errorf("invalid request")
	}

	nonce := ct[:nonceSize]
	ct = ct[nonceSize:]

	pt, err := m.aead.Open(nil, nonce, ct, []byte(req.AdditionalAuthenticatedData))
	if err != nil {
		return nil, err
	}

	return &secretlock.DecryptResponse{
		Plaintext: string(pt),
	}, nil
}

func NewMasterLock(passphrase string, h func() hash.Hash, salt []byte) (secretlock.Service, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase is empty")
	}

	if h == nil {
		return nil, fmt.Errorf("hash is nil")
	}

	size := h().Size()
	if size > sha256.Size {
		return nil, fmt.Errorf("hash size is too large")
	}

	expaneder := hkdf.New(h, []byte(passphrase), salt, nil)
	masterKey := make([]byte, size)

	_, err := io.ReadFull(expaneder, masterKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipherutil.CreateAESCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return &masterLockHKDF{
		h:    h,
		salt: salt,
		aead: aead,
	}, nil
}
