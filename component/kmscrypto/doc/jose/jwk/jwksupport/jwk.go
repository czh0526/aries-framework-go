package jwksupport

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/go-jose/go-jose/v3"
)

const (
	ecKty          = "EC"
	okpKty         = "OKP"
	x25519Crv      = "X25519"
	bls12381G2Crv  = "BLS12381_G2"
	bls12381G2Size = 96
)

func JWKFromKey(opaqueKey interface{}) (*jwk.JWK, error) {
	key := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: opaqueKey,
		},
	}

	// marshal/unmarshal to get all JWK's fields other than Key filled.
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK: %v", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK: %v", err)
	}

	return key, nil
}

func JWKFromX25519Key(pubKey []byte) (*jwk.JWK, error) {
	key := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: pubKey,
		},
		Crv: x25519Crv,
		Kty: okpKty,
	}

	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK failed: err = %v", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK failed, err = %v", err)
	}

	return key, nil
}
