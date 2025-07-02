package subtle

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"hash"
	"math/big"
)

var errInvalidSecp256K1Signature = errors.New("secp256k1_verifier: invalid signature")

type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
	hashFunc  func() hash.Hash
	encoding  string
}

func NewSecp256K1Verifier(hashAlg, curve, encoding string, x, y []byte) (*ECDSAVerifier, error) {
	publicKey := &ecdsa.PublicKey{
		Curve: GetCurve(curve),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	return NewSecp256K1VerifierFromPublicKey(hashAlg, encoding, publicKey)
}

func NewSecp256K1VerifierFromPublicKey(hashAlg, encoding string, publicKey *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if publicKey.Curve == nil {
		return nil, errors.New("ecdsa_verifier: invalid curve")
	}

	curve := ConvertCurveName(publicKey.Curve.Params().Name)
	if err := ValidateSecp256K1Params(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("ecdsa_verifier: %w", err)
	}

	hashFunc := subtle.GetHashFunc(hashAlg)
	return &ECDSAVerifier{
		publicKey: publicKey,
		hashFunc:  hashFunc,
		encoding:  encoding,
	}, nil
}

func (v *ECDSAVerifier) Verify(signatureBytes, data []byte) error {
	signature, err := DecodeSecp256K1Signature(signatureBytes, v.encoding)
	if err != nil {
		return fmt.Errorf("secp256k1_verifier: %w", err)
	}

	hashed, err := subtle.ComputeHash(v.hashFunc, data)
	if err != nil {
		return err
	}

	valid := ecdsa.Verify(v.publicKey, hashed, signature.R, signature.S)
	if !valid {
		return errInvalidSecp256K1Signature
	}

	return nil
}
