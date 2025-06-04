package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"math/big"
)

func ToECKey(key *spicrypto.PublicKey) (*ecdsa.PublicKey, error) {
	crv, err := toCurve(key.Curve)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(key.X),
		Y:     new(big.Int).SetBytes(key.Y),
	}, nil
}

func toCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256", "NIST_P256":
		return elliptic.P256(), nil
	case "P-384", "NIST_P384":
		return elliptic.P384(), nil
	case "P-521", "NIST_P521":
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("invalid curvce '%s'", crv)
}
