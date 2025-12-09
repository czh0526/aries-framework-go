package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	signatureapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	gojose "github.com/go-jose/go-jose/v3"
	"math/big"
)

const (
	p256KeySize      = 32
	p384KeySize      = 48
	p521KeySize      = 66
	secp256k1KeySize = 32
)

type SignatureVerifier interface {
	KeyType() string
	Curve() string
	Algorithm() string
	Verify(pubKey *signatureapi.PublicKey, msg, signature []byte) error
}

var _ SignatureVerifier = (*ECDSASignatureVerifier)(nil)

type baseSignatureVerifier struct {
	keyType   string
	curve     string
	algorithm string
}

func (b baseSignatureVerifier) KeyType() string {
	return b.keyType
}

func (b baseSignatureVerifier) Curve() string {
	return b.curve
}

func (b baseSignatureVerifier) Algorithm() string {
	return b.algorithm
}

type ellipticCurve struct {
	curve   elliptic.Curve
	keySize int
	hash    crypto.Hash
}

type ECDSASignatureVerifier struct {
	baseSignatureVerifier

	ec ellipticCurve
}

func (e *ECDSASignatureVerifier) Verify(pubKey *signatureapi.PublicKey, msg, signature []byte) error {
	pubKeyJWK := pubKey.JWK
	if pubKeyJWK == nil {
		j, err := e.createJWK(pubKey.Value)
	}

	//

	// 计算 msg 的 hash 值
	hasher := e.ec.hash.New()
	_, err := hasher.Write(msg)
	if err != nil {
		return errors.New("ecdsa: hash error")
	}
	hash := hasher.Sum(nil)

	// 提取 r,s 值
	var r, s *big.Int
	if len(signature) > 2*e.ec.keySize {
		var esig struct {
			R, S *big.Int
		}

		if _, err := asn1.Unmarshal(signature, &esig); err != nil {
			return err
		}
		r = esig.R
		s = esig.S
	} else {
		r = big.NewInt(0).SetBytes(signature[:e.ec.keySize])
		s = big.NewInt(0).SetBytes(signature[e.ec.keySize:])
	}

	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
}

func (e *ECDSASignatureVerifier) createJWK(pubKeyBytes []byte) (*jwk.JWK, error) {
	curve := e.ec.curve

	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	if x == nil {
		return nil, errors.New("invalid public key")
	}

	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return &jwk.JWK{
		JSONWebKey: gojose.JSONWebKey{
			Key:       ecdsaPubKey,
			Algorithm: e.algorithm,
		},
		Kty: e.keyType,
		Crv: e.curve,
	}, nil
}

func NewECDSAES256SignatureVerifier() *ECDSASignatureVerifier {
	return &ECDSASignatureVerifier{
		baseSignatureVerifier: baseSignatureVerifier{
			keyType:   "EC",
			curve:     "P-256",
			algorithm: "ES256",
		},
		ec: ellipticCurve{
			curve:   elliptic.P256(),
			keySize: p256KeySize,
			hash:    crypto.SHA256,
		},
	}
}

type Ed25519SignatureVerifier struct {
	baseSignatureVerifier
}

type RSAPS256SignatureVerifier struct {
	baseSignatureVerifier
}

type RSARS256SignatureVerifier struct {
	baseSignatureVerifier
}

type PublicKeyVerifier struct {
	exactType      string
	singleVerifier SignatureVerifier
	verifiers      []SignatureVerifier
}
