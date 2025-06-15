package keywrapper

import (
	"encoding/base64"
	"errors"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/tink-crypto/tink-go/v2/tink"
	"regexp"
)

type LocalAEAD struct {
	keyURI     string
	secretLock spisecretlock.Service
}

func New(secretLock spisecretlock.Service, keyURI string) (tink.AEAD, error) {
	uri, err := trimPrefix(keyURI)
	if err != nil {
		return nil, err
	}

	return &LocalAEAD{
		keyURI:     uri,
		secretLock: secretLock,
	}, nil
}

func (a *LocalAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	req := &spisecretlock.EncryptRequest{
		Plaintext:                   base64.URLEncoding.EncodeToString(plaintext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(additionalData),
	}

	resp, err := a.secretLock.Encrypt(a.keyURI, req)
	if err != nil {
		return nil, err
	}

	ct, err := base64.URLEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (a *LocalAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	req := &spisecretlock.DecryptRequest{
		Ciphertext:                  base64.URLEncoding.EncodeToString(ciphertext),
		AdditionalAuthenticatedData: base64.URLEncoding.EncodeToString(additionalData),
	}

	resp, err := a.secretLock.Decrypt(a.keyURI, req)
	if err != nil {
		return nil, err
	}

	pt, err := base64.URLEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func trimPrefix(keyURI string) (string, error) {
	re1 := regexp.MustCompile(`[a-zA-Z0-9-_]+://`)
	loc := re1.FindStringIndex(keyURI)

	if len(loc) == 0 || loc[0] > 0 {
		return "", errors.New("keyURI must have a prefix in form `prefixname://`")
	}
	if loc[1] <= len(keyURI) {
		return "", errors.New("keyURI can't consist only from a prefix")
	}

	return keyURI[loc[1]:], nil
}
