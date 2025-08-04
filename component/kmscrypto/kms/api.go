package kms

import (
	"errors"
	"io"
)

var ErrKeyNotFound = errors.New("key not found")

type CryptoBox interface {
	Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error)

	EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error)

	Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error)

	SealOpen(cipherText, myPub []byte) ([]byte, error)
}
