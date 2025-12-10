package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
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
	// 获取 JWK
	pubKeyJWK := pubKey.JWK
	if pubKeyJWK == nil {
		j, err := e.createJWK(pubKey.Value)
		if err != nil {
			return fmt.Errorf("ecdsa: create JWK from public key bytes: %w", err)
		}
		pubKeyJWK = j
	}

	// 获取 public Key
	ecdsaPubKey, ok := pubKeyJWK.Key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("ecdsa: invalid public key type")
	}

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

	// ecdsa 需要参数 pubKey 是 *PublicKey
	verified := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if !verified {
		return errors.New("ecdsa: invalid signature")
	}

	return nil
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

func NewECDSAES384SignatureVerifier() *ECDSASignatureVerifier {
	return &ECDSASignatureVerifier{
		baseSignatureVerifier: baseSignatureVerifier{
			keyType:   "EC",
			curve:     "P-384",
			algorithm: "ES384",
		},
		ec: ellipticCurve{
			curve:   elliptic.P384(),
			keySize: p384KeySize,
			hash:    crypto.SHA384,
		},
	}
}

func NewECDSAES521SignatureVerifier() *ECDSASignatureVerifier {
	return &ECDSASignatureVerifier{
		baseSignatureVerifier: baseSignatureVerifier{
			keyType:   "EC",
			curve:     "P-521",
			algorithm: "ES521",
		},
		ec: ellipticCurve{
			curve:   elliptic.P521(),
			keySize: p521KeySize,
			hash:    crypto.SHA512,
		},
	}
}

func NewECDSASecp256k1SignatureVerifier() *ECDSASignatureVerifier {
	return &ECDSASignatureVerifier{
		baseSignatureVerifier: baseSignatureVerifier{
			keyType:   "EC",
			curve:     "secp256k1",
			algorithm: "ES256K",
		},
		ec: ellipticCurve{
			curve:   btcec.S256(),
			keySize: secp256k1KeySize,
			hash:    crypto.SHA256,
		},
	}
}

type Ed25519SignatureVerifier struct {
	baseSignatureVerifier
}

func (s Ed25519SignatureVerifier) Verify(pubKey *signatureapi.PublicKey, msg, signature []byte) error {
	value := pubKey.Value
	if pubKey.JWK != nil {
		var ok bool
		value, ok = pubKey.JWK.Public().Key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("public key not ed25519.VerificationMethod")
		}
	}

	if len(value) != ed25519.PublicKeySize {
		return errors.New("ed25519: invalid key")
	}

	// ed25519 需要参数 pubKey 是字节数组
	verified := ed25519.Verify(value, msg, signature)
	if !verified {
		return errors.New("ed25519: invalid signature")
	}

	return nil
}

func NewEd25519SignatureVerifier() *Ed25519SignatureVerifier {
	return &Ed25519SignatureVerifier{
		baseSignatureVerifier{
			keyType:   "OKP",
			curve:     "Ed25519",
			algorithm: "EdDSA",
		},
	}
}

type RSAPS256SignatureVerifier struct {
	baseSignatureVerifier
}

func (r RSAPS256SignatureVerifier) Verify(jwPubKey *signatureapi.PublicKey, msg, signature []byte) error {
	pubKey, err := x509.ParsePKCS1PublicKey(jwPubKey.Value)
	if err != nil {
		return errors.New("rsa: invalid public key")
	}

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(msg)
	if err != nil {
		return errors.New("rsa: hash error")
	}
	hashed := hasher.Sum(nil)

	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed, signature, nil)
	if err != nil {
		return errors.New("rsa: invalid signature")
	}

	return nil
}

func NewRSAPS256SignatureVerifier() *RSAPS256SignatureVerifier {
	return &RSAPS256SignatureVerifier{
		baseSignatureVerifier: baseSignatureVerifier{
			keyType:   "RSA",
			algorithm: "PS256",
		},
	}
}

type RSARS256SignatureVerifier struct {
	baseSignatureVerifier
}

func (r RSARS256SignatureVerifier) Verify(jwPubKey *signatureapi.PublicKey, msg, signature []byte) error {
	pubKey, err := x509.ParsePKCS1PublicKey(jwPubKey.Value)
	if err != nil {
		return errors.New("not *rsa.VerificationMethod public key")
	}

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(msg)
	if err != nil {
		return err
	}
	hashed := hasher.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, signature)
}

func NewRSARS256SignatureVerifier() *RSARS256SignatureVerifier {
	return &RSARS256SignatureVerifier{
		baseSignatureVerifier: baseSignatureVerifier{
			keyType:   "RSA",
			algorithm: "RS256",
		},
	}
}

type PublicKeyVerifier struct {
	exactType      string
	singleVerifier SignatureVerifier
	verifiers      []SignatureVerifier
}
