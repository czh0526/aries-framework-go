package secretlock

import "github.com/czh0526/aries-framework-go/spi/secretlock"

type MockSecretLock struct {
	ValEncrypt string
	ValDecrypt string
	ErrEncrypt error
	ErrDecrypt error
}

func (m *MockSecretLock) Encrypt(keyURI string, req *secretlock.EncryptRequest) (*secretlock.EncryptResponse, error) {
	if m.ErrEncrypt != nil {
		return nil, m.ErrEncrypt
	}

	return &secretlock.EncryptResponse{
		Ciphertext: m.ValEncrypt,
	}, nil
}

func (m *MockSecretLock) Decrypt(keyURI string, req *secretlock.DecryptRequest) (*secretlock.DecryptResponse, error) {
	if m.ErrDecrypt != nil {
		return nil, m.ErrDecrypt
	}

	return &secretlock.DecryptResponse{
		Plaintext: m.ValDecrypt,
	}, nil
}
