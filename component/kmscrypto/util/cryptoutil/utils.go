package cryptoutil

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/teserakt-io/golang-ed25519/extra25519"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const Curve25519KeySize = 32
const NonceSize = 24

func DeriveECDHX25519(fromPrivKey, toPubKey *[chacha.KeySize]byte) ([]byte, error) {
	if fromPrivKey == nil || toPubKey == nil {
		return nil, errors.New("deriveECDHX25519: invalid key")
	}

	z, err := curve25519.X25519(fromPrivKey[:], toPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("deriveECDHX25519: %w", err)
	}

	return z, nil
}

func LengthPrefix(array []byte) []byte {
	const prefixLen = 4

	arrInfo := make([]byte, prefixLen+len(array))
	binary.BigEndian.PutUint32(arrInfo, uint32(len(array)))
	copy(arrInfo[prefixLen:], array)

	return arrInfo
}

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
