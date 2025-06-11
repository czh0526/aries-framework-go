package subtle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
	"hash"
	"math/big"
)

type Secp256K1Signer struct {
	privateKey *ecdsa.PrivateKey
	hashFunc   func() hash.Hash
	encoding   string
}

func (e *Secp256K1Signer) Sign(data []byte) ([]byte, error) {
	hashed, err := subtle.ComputeHash(e.hashFunc, data)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hashed)
	if err != nil {
		return nil, err
	}

	sig := NewSecp256K1Signature(r, s)

	ret, err := sig.EncodeSecp256K1Signature(
		e.encoding, e.privateKey.PublicKey.Curve.Params().Name)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer: failed to encode signature: %w", err)
	}

	return ret, nil
}

var _ tink.Signer = (*Secp256K1Signer)(nil)

func NewSecp256K1Signer(hashAlg string,
	curve string,
	encoding string,
	keyValue []byte) (*Secp256K1Signer, error) {

	privKey := new(ecdsa.PrivateKey)
	c := GetCurve(curve)
	privKey.PublicKey.Curve = c
	privKey.PublicKey.X, privKey.PublicKey.Y = c.ScalarBaseMult(keyValue)
	privKey.D = new(big.Int).SetBytes(keyValue)

	return NewSecp256K1SignerFromPrivateKey(hashAlg, encoding, privKey)
}

func NewSecp256K1SignerFromPrivateKey(hashAlg string,
	encoding string,
	privateKey *ecdsa.PrivateKey) (*Secp256K1Signer, error) {
	if privateKey.Curve == nil {
		return nil, errors.New("secp256k1_signer: privateKey.Curve can't be nil")
	}

	curve := ConvertCurveName(privateKey.Curve.Params().Name)
	if err := ValidateSecp256K1Params(hashAlg, curve, encoding); err != nil {
		return nil, fmt.Errorf("scp256k1_signer: %w", err)
	}

	hashFunc := subtle.GetHashFunc(hashAlg)

	return &Secp256K1Signer{
		privateKey: privateKey,
		hashFunc:   hashFunc,
		encoding:   encoding,
	}, nil
}

func ConvertCurveName(name string) string {
	switch name {
	case "secp256k1", "secp256K1":
		return "SECP256K1"
	default:
		return ""
	}
}
