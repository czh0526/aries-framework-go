package jwksupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
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

func PublicKeyFromJWK(jwkKey *jwk.JWK) (*spicrypto.PublicKey, error) {
	if jwkKey == nil {
		return nil, errors.New("publicKeyFromJWK: jwk is empty")
	}

	pubKey := &spicrypto.PublicKey{
		KID:   jwkKey.KeyID,
		Curve: jwkKey.Crv,
		Type:  jwkKey.Kty,
	}

	switch key := jwkKey.Key.(type) {
	case *ecdsa.PublicKey:
		pubKey.X = key.X.Bytes()
		pubKey.Y = key.Y.Bytes()

	case *ecdsa.PrivateKey:
		pubKey.X = key.X.Bytes()
		pubKey.Y = key.Y.Bytes()

	case *bbs12381g2pub.PublicKey:
		return nil, errors.New("publicKeyFromJWK: unsupported key type BBS+")

	case *bbs12381g2pub.PrivateKey:
		return nil, errors.New("publicKeyFromJWK: unsupported key type BBS+")

	case ed25519.PublicKey:
		pubKey.X = key

	case ed25519.PrivateKey:
		var ok bool
		pubEdKey, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("publicKeyFromJWK: invalid 25519 private key")
		}

		pubKey.X = pubEdKey
	}

	return pubKey, nil
}
