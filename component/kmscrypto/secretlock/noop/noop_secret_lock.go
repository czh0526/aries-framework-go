package noop

import spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"

type NoLock struct{}

func (s *NoLock) Encrypt(keyURI string, req *spisecretlock.EncryptRequest) (
	*spisecretlock.EncryptResponse, error) {
	return &spisecretlock.EncryptResponse{
		Ciphertext: req.Plaintext,
	}, nil
}

func (s *NoLock) Decrypt(keyURI string, req *spisecretlock.DecryptRequest) (
	*spisecretlock.DecryptResponse, error) {
	return &spisecretlock.DecryptResponse{
		Plaintext: req.Ciphertext,
	}, nil
}
