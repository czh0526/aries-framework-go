package cryptoutil

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/teserakt-io/golang-ed25519/extra25519"
)

const Curve25519KeySize = 32

func PublicEd25519toCurve25519(pub []byte) ([]byte, error) {
	if len(pub) == 0 {
		return nil, errors.New("public key is nil")
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d-byte key size is invalid", len(pub))
	}

	pkOut := new([Curve25519KeySize]byte)
	pkIn := new([Curve25519KeySize]byte)
	copy(pkIn[:], pub)

	success := extra25519.PublicKeyToCurve25519(pkOut, pkIn)
	if !success {
		return nil, errors.New("error converting public key")
	}

	return pkOut[:], nil
}

func SecretEd25519toCurve25519(priv []byte) ([]byte, error) {
	if len(priv) == 0 {
		return nil, errors.New("private key is nil")
	}

	skIn := new([ed25519.PrivateKeySize]byte)
	skOut := new([Curve25519KeySize]byte)
	copy(skIn[:], priv)

	extra25519.PrivateKeyToCurve25519(skOut, skIn)
	return skOut[:], nil
}
