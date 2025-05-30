package jwkkid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"math/big"
)

// secp256k1Thumbprint 为 secp256k1 类型的 keyBytes 生成指纹
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
	coordLength := jwk.CurveSize(curve)

	if len(x.Bytes()) > coordLength || len(y.Bytes()) > coordLength {
		return "", errors.New("invalid elliptic secp256k1 key (too large)")
	}

	return fmt.Sprintf(ecSecp256K1ThumbprintTemplate,
		jwk.NewFixedSizeBuffer(x.Bytes(), coordLength).Base64(),
		jwk.NewFixedSizeBuffer(y.Bytes(), coordLength).Base64()), nil
}
