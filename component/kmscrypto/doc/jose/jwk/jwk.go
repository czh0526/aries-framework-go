package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/go-jose/go-jose/v3"
	"strings"
)

const (
	secp256k1Alg  = "ES256K"
	secp256k1Crv  = "secp256k1"
	secp256k1Size = 32
	bitsPerByte   = 8
	ecKty         = "EC"
	okpKty        = "OKP"
	x25519Crv     = "X25519"
	ed25519Crv    = "Ed25519"
	bls12381G2Crv = "BLS12381_G2"
)

type JWK struct {
	jose.JSONWebKey

	Kty string
	Crv string
}

func (j *JWK) PublicKeyBytes() ([]byte, error) {
	if j.isBLS12381G2() {
		return nil, fmt.Errorf("I can't handle BLS12381G2 Key")
	}

	if j.isX25519() {
		x25519Key, ok := j.Key.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid public key in kid `%s`", j.KeyID)
		}

		return x25519Key, nil
	}

	if j.isSecp256k1() {
		var ecPubKey *ecdsa.PublicKey
		ecPubKey, ok := j.Key.(*ecdsa.PublicKey)
		if !ok {
			ecPubKey = &j.Key.(*ecdsa.PrivateKey).PublicKey
		}

		pubKey := &btcec.PublicKey{
			Curve: btcec.S256(),
			X:     ecPubKey.X,
			Y:     ecPubKey.Y,
		}

		return pubKey.SerializeCompressed(), nil
	}

	switch pubKey := j.Public().Key.(type) {
	case ed25519.PublicKey:
		return pubKey, nil
	case *ecdsa.PublicKey:
		return elliptic.Marshal(pubKey, pubKey.X, pubKey.Y), nil
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(pubKey), nil
	default:
		return nil, fmt.Errorf("unsupported public key type in kid `%s`", j.KeyID)
	}
}

func (j *JWK) isBLS12381G2() bool {
	switch j.Key.(type) {
	case *bbs12381g2pub.PublicKey,
		*bbs12381g2pub.PrivateKey:
		return true
	default:
		return false
	}
}

func (j *JWK) isX25519() bool {
	switch j.Key.(type) {
	case []byte:
		return isX25519(j.Kty, j.Crv)
	default:
		return false
	}
}

func (j *JWK) isSecp256k1() bool {
	return isSecp256k1Key(j.Key) ||
		isSecp256k1(j.Algorithm, j.Kty, j.Crv)
}

func (j *JWK) KeyType() (spikms.KeyType, error) {
	switch key := j.Key.(type) {
	case ed25519.PrivateKey, ed25519.PublicKey:
		return spikms.ED25519Type, nil
	case *bbs12381g2pub.PublicKey, *bbs12381g2pub.PrivateKey:
		return spikms.BLS12381G2Type, nil
	case *ecdsa.PublicKey:
		return ecdsaPubKeyType(key)
	case *ecdsa.PrivateKey:
		return ecdsaPubKeyType(&(key.PublicKey))
	case *rsa.PublicKey, *rsa.PrivateKey:
		return spikms.RSAPS256Type, nil
	}

	switch {
	case isX25519(j.Kty, j.Crv):
		return spikms.X25519ECDHKWType, nil
	case isEd25519(j.Kty, j.Crv):
		return spikms.ED25519Type, nil
	case isSecp256k1(j.Algorithm, j.Kty, j.Crv):
		return spikms.ECDSASecp256k1TypeIEEEP1363, nil
	default:
		return "", fmt.Errorf("no keytype recognized for jwk")
	}
}

func ecdsaPubKeyType(pub *ecdsa.PublicKey) (spikms.KeyType, error) {
	switch pub.Curve {
	case btcec.S256():
		return spikms.ECDSASecp256k1TypeIEEEP1363, nil
	case elliptic.P256():
		return spikms.ECDSAP256TypeIEEEP1363, nil
	case elliptic.P384():
		return spikms.ECDSAP384TypeIEEEP1363, nil
	case elliptic.P521():
		return spikms.ECDSAP521TypeIEEEP1363, nil
	}

	return "", fmt.Errorf("no keytype recognized for ecdsa jwk")
}

func isSecp256k1Key(pubKey interface{}) bool {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == btcec.S256()
	case *ecdsa.PrivateKey:
		return key.Curve == btcec.S256()
	default:
		return false
	}
}

func isSecp256k1(alg, kty, crv string) bool {
	return strings.EqualFold(alg, secp256k1Alg) ||
		(strings.EqualFold(kty, ecKty) && strings.EqualFold(crv, secp256k1Crv))
}

func isX25519(kty, crv string) bool {
	return strings.EqualFold(kty, okpKty) && strings.EqualFold(crv, x25519Crv)
}

func isEd25519(kty, crv string) bool {
	return strings.EqualFold(kty, okpKty) && strings.EqualFold(crv, ed25519Crv)
}

func isBLS12381G2(kty, crv string) bool {
	return strings.EqualFold(kty, ecKty) && strings.EqualFold(crv, bls12381G2Crv)
}
