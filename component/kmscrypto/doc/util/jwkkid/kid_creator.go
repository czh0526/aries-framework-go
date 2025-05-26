package jwkkid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"math/big"
)

func CreateKID(keyBytes []byte, kt spikms.KeyType) (string, error) {
	if len(keyBytes) == 0 {
		return "", errors.New("createKID: empty key")
	}

	switch kt {
	case spikms.X25519ECDHKWType:
		x25519KID, err := createX25519KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %v", err)
		}

		return x25519KID, nil

	case spikms.BLS12381G2Type:
		bbsKID, err := createBLS12381G2KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %v", err)
		}

		return bbsKID, nil

	case spikms.ECDSASecp256k1TypeDER, spikms.ECDSASecp256k1TypeIEEEP1363:
		secp256k1KID, err := secp256k1Thumbprint(keyBytes, kt)
		if err != nil {
			return "", fmt.Errorf("createKID: %v", err)
		}

		return secp256k1KID, nil
	}

	j, err := BuildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to build jwk: %v", err)
	}

	tp, err := j.Th
}

func sha256Sum(j string) []byte {
	h := crypto.SHA256.New()
	_, _ = h.Write([]byte(j))

	return h.Sum(nil)
}

func secp256k1Thumbprint(keyBytes []byte, kt spikms.KeyType) (string, error) {
	switch kt {
	case spikms.ECDSASecp256k1TypeIEEEP1363:
	case spikms.ECDSASecp256k1TypeDER:
	default:
		return "", fmt.Errorf("secp256k1Thumbprint: invalid key type: %s", kt)
	}

	j, err := BuildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("secp256k1Thumbprint: failed to build jwk: %v", err)
	}

	var input string
	switch key := j.Key.(type) {
	case *ecdsa.PublicKey:
		input, err = secp256k1ThumbprintInput(key.Curve, key.X, key.Y)
		if err != nil {
			return "", fmt.Errorf("secp256k1Thumbprint: failed to get public key thumbprint input: %v", err)
		}

	case *ecdsa.PrivateKey:
		input, err = secp256k1ThumbprintInput(key.Curve, key.X, key.Y)
		if err != nil {
			return "", fmt.Errorf("secp256k1Thumbprint: failed to get private key thumbprint input: %v", err)
		}
	default:
		return "", fmt.Errorf("secp256k1Thumbprint: unknown key type: %T", key)
	}

	thumbprint := sha256Sum(input)

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func secp256k1ThumbprintInput(curve elliptic.Curve, x, y *big.Int) (string, error) {
	ecSecp256K1ThumbprintTemplate := `{"crv":"SECP256K1","kty":"EC","x":"%s","y":"%s"}`
	coordLength := curveSize(curve)

	if len(x.Bytes()) > coordLength || len(y.Bytes()) > coordLength {
		return "", errors.New("invalid elliptic secp256k1 key (too large)")
	}
}

func BuildJWK(keyBytes []byte, kt spikms.KeyType) (*jwk.JWK, error) {
	var (
		j   *jwk.JWK
		err error
	)

	switch kt {
	case spikms.ECDSAP256TypeDER, spikms.ECDSAP384TypeDER,
		spikms.ECDSAP521TypeDER, spikms.ECDSASecp256k1DER:
		j, err = generateJWKFromDERECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: faild to build JWK from ecdsa DER key: %v", err)
		}

	case spikms.ED25519Type:
		j, err = jwksupport.JWKFromKey(ed25519.PublicKey(keyBytes))
		if err != nil {
			return nil, fmt.Errorf("buildJWK: faild to build JWK from key: %v", err)
		}

	case spikms.ECDSAP256TypeIEEEP1363, spikms.ECDSAP384IEEEP1363,
		spikms.ECDSAP521TypeIEEEP1363, spikms.ECDSASecp256k1TypeIEEEP1363:

	case spikms.NISTP256ECDHKWType, spikms.NISTP384ECDHKWType, spikms.NISTP521ECDHKWType:

	case spikms.X25519ECDHKWType:
	}
}

func generateJWKFromDERECDSA(keyBytes []byte) (*jwk.JWK, error) {
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: %v", err)
	}

	return jwksupport.JWKFromKey(pubKey)
}
