package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/go-jose/go-jose/v3"
)

type jsonWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`

	X *ByteBuffer `json:"x,omitempty"`
	Y *ByteBuffer `json:"y,omitempty"`

	D *ByteBuffer `json:"d,omitempty"`
}

func (j *JWK) UnmarshalJSON(jwkBytes []byte) error {
	var key jsonWebKey

	marshalErr := json.Unmarshal(jwkBytes, &key)
	if marshalErr != nil {
		return fmt.Errorf("unable to read JWKL %v", marshalErr)
	}

	if isSecp256k1(key.Alg, key.Kty, key.Crv) {
		jwk, err := unmarshalSecp256k1(&key)
		if err != nil {
			return fmt.Errorf("unable to read JWK: %v", err)
		}

		*j = *jwk

	} else if isBLS12381G2(key.Kty, key.Crv) {
		jwk, err := unmarshalBLS112381G2(&key)
		if err != nil {
			return fmt.Errorf("unable to read BBS+ JWE: %v", err)
		}

		*j = *jwk

	} else if isX25519(key.Kty, key.Crv) {
		jwk, err := unmarshalX25519(&key)
		if err != nil {
			return fmt.Errorf("unable to read X25519 JWE: %v", err)
		}

		*j = *jwk

	} else {
		var joseJWK jose.JSONWebKey

		err := json.Unmarshal(jwkBytes, &joseJWK)
		if err != nil {
			return fmt.Errorf("unable to read jose JWK, %v", err)
		}

		j.JSONWebKey = joseJWK
	}

	j.Kty = key.Kty
	j.Crv = key.Crv

	return nil
}

func (j *JWK) MarshalJSON() ([]byte, error) {
	if j.isSecp256k1() {
		return marshalSecp256k1(j)
	}
	if j.isX25519() {
		return marshalX25519(j)
	}
	if j.isBLS12381G2() {
		return marshalBLS12381G2(j)
	}

	return (&j.JSONWebKey).MarshalJSON()
}

func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / bitsPerByte

	if bitLen%bitsPerByte != 0 {
		size++
	}

	return size
}

func marshalSecp256k1(jwk *JWK) ([]byte, error) {
	var raw jsonWebKey

	switch ecdsaKey := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		raw = jsonWebKey{
			Kty: ecKty,
			Crv: secp256k1Crv,
			X:   NewFixedSizeBuffer(ecdsaKey.X.Bytes(), secp256k1Size),
		}
	case *ecdsa.PrivateKey:
		raw = jsonWebKey{
			Kty: ecKty,
			Crv: secp256k1Crv,
			X:   NewFixedSizeBuffer(ecdsaKey.X.Bytes(), secp256k1Size),
			Y:   NewFixedSizeBuffer(ecdsaKey.Y.Bytes(), secp256k1Size),
			D:   NewFixedSizeBuffer(ecdsaKey.D.Bytes(), dSize(ecdsaKey.Curve)),
		}
	}

	raw.Kid = jwk.KeyID
	raw.Alg = jwk.Algorithm
	raw.Use = jwk.Use

	return json.Marshal(raw)
}

func unmarshalSecp256k1(jwk *jsonWebKey) (*JWK, error) {
	if jwk.X == nil {
		return nil, ErrInvalidKey
	}
	if jwk.Y == nil {
		return nil, ErrInvalidKey
	}
	curve := btcec.S256()

	if CurveSize(curve) != len(jwk.X.data) {
		return nil, ErrInvalidKey
	}
	if CurveSize(curve) != len(jwk.Y.data) {
		return nil, ErrInvalidKey
	}

	if jwk.D != nil && dSize(curve) != len(jwk.D.data) {
		return nil, ErrInvalidKey
	}

	x := jwk.X.bigInt()
	y := jwk.Y.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidKey
	}

	var key interface{}
	if jwk.D != nil {
		key = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: jwk.D.bigInt(),
		}
	} else {
		key = &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	}

	return &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       key,
			KeyID:     jwk.Kid,
			Algorithm: jwk.Alg,
			Use:       jwk.Use,
		},
		Crv: jwk.Crv,
		Kty: jwk.Kty,
	}, nil
}

func marshalX25519(jwk *JWK) ([]byte, error) {
	var raw jsonWebKey

	key, ok := jwk.Key.([]byte)
	if !ok {
		return nil, errors.New("marshalX25519: invalid key")
	}

	if len(key) != cryptoutil.Curve25519KeySize {
		return nil, errors.New("marshalX25519: invalid key")
	}

	raw = jsonWebKey{
		Kty: okpKty,
		Crv: x25519Crv,
		X:   NewFixedSizeBuffer(key, cryptoutil.Curve25519KeySize),
	}

	raw.Kid = jwk.KeyID
	raw.Alg = jwk.Algorithm
	raw.Use = jwk.Use

	return json.Marshal(raw)
}

func unmarshalX25519(jwk *jsonWebKey) (*JWK, error) {
	if jwk.X == nil {
		return nil, ErrInvalidKey
	}

	if len(jwk.X.data) != cryptoutil.Curve25519KeySize {
		return nil, ErrInvalidKey
	}

	return &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       jwk.X.data,
			KeyID:     jwk.Kid,
			Algorithm: jwk.Alg,
			Use:       jwk.Use,
		},
		Crv: jwk.Crv,
		Kty: jwk.Kty,
	}, nil
}

func marshalBLS12381G2(jwk *JWK) ([]byte, error) {
	return nil, errors.New("marshalBLS12381G2: unsupported key type: BLS12381G2")
}

func unmarshalBLS112381G2(jwk *jsonWebKey) (*JWK, error) {
	return nil, errors.New("unmarshalBLS112381G2: unsupported key type: BLS12381G2")
}

var ErrInvalidKey = errors.New("invalid JWK")
