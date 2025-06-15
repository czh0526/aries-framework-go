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
	"github.com/btcsuite/btcd/btcec"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"math/big"
)

var errInvalidKeyType = errors.New("key type is not supported")

// CreateKID 创建一个 KID
func CreateKID(keyBytes []byte, kt spikms.KeyType) (string, error) {
	if len(keyBytes) == 0 {
		return "", errors.New("createKID: empty key")
	}

	switch kt {
	case spikms.X25519ECDHKWType:
		// 反序列化 JSON 对象
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

	// 从字节数组中提取公钥
	j, err := BuildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to build jwk: %v", err)
	}

	tp, err := j.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to get jwk thumbprint: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func sha256Sum(j string) []byte {
	h := crypto.SHA256.New()
	_, _ = h.Write([]byte(j))

	return h.Sum(nil)
}

// BuildJWK 构建 JWK 对象
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
		c := getCurveByKMSKeyType(kt)
		x, y := elliptic.Unmarshal(c, keyBytes)

		pubKey := &ecdsa.PublicKey{
			Curve: c,
			X:     x,
			Y:     y,
		}

		j, err = jwksupport.JWKFromKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdsa key in IEEE1363 format: %v", err)
		}

	case spikms.NISTP256ECDHKWType, spikms.NISTP384ECDHKWType, spikms.NISTP521ECDHKWType:
		j, err = generateJWKFromECDH(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdh key, err = %v", err)
		}

	case spikms.X25519ECDHKWType:
		pubKey, err := unmarshalECDHKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to unmarshal public key from X25519 key, err = %v", err)
		}

		j, err = jwksupport.JWKFromX25519Key(pubKey.X)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from X25519 key, err = %v", err)
		}
	default:
		return nil, fmt.Errorf("buildJWK: %w: `%s`", errInvalidKeyType, kt)
	}

	return j, nil
}

func generateJWKFromDERECDSA(keyBytes []byte) (*jwk.JWK, error) {
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: %v", err)
	}

	return jwksupport.JWKFromKey(pubKey)
}

func generateJWKFromECDH(keyBytes []byte) (*jwk.JWK, error) {
	compositeKey, err := unmarshalECDHKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromECDH: unmarshalECDHKey failed, err = %v", err)
	}

	c, err := hybrid.GetCurve(compositeKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromECDH: get Curve for ECDH key failed, err = %v", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(compositeKey.X),
		Y:     new(big.Int).SetBytes(compositeKey.Y),
	}

	return jwksupport.JWKFromKey(pubKey)
}

func getCurveByKMSKeyType(kt spikms.KeyType) elliptic.Curve {
	switch kt {
	case spikms.ECDSAP256TypeIEEEP1363:
		return elliptic.P256()

	case spikms.ECDSAP384TypeIEEEP1363:
		return elliptic.P384()

	case spikms.ECDSAP521TypeIEEEP1363:
		return elliptic.P521()

	case spikms.ECDSASecp256k1TypeIEEEP1363:
		return btcec.S256()
	}

	return elliptic.P256()
}
