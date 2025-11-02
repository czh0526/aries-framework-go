package fingerprint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
)

const (
	// X25519PubKeyMultiCodec for Curve25519 public key in multicodec table.
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	X25519PubKeyMultiCodec = 0xec
	// ED25519PubKeyMultiCodec for Ed25519 public key in multicodec table.
	ED25519PubKeyMultiCodec = 0xed
	// BLS12381g2PubKeyMultiCodec for BLS12-381 G2 public key in multicodec table.
	BLS12381g2PubKeyMultiCodec = 0xeb
	// BLS12381g1g2PubKeyMultiCodec for BLS12-381 G1G2 public key in multicodec table.
	BLS12381g1g2PubKeyMultiCodec = 0xee
	// P256PubKeyMultiCodec for NIST P-256 public key in multicodec table.
	P256PubKeyMultiCodec = 0x1200
	// P384PubKeyMultiCodec for NIST P-384 public key in multicodec table.
	P384PubKeyMultiCodec = 0x1201
	// P521PubKeyMultiCodec for NIST P-521 public key in multicodec table.
	P521PubKeyMultiCodec = 0x1202

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48
)

func CreateDIDKey(pubKey []byte) (string, string) {
	return CreateDIDKeyByCode(ED25519PubKeyMultiCodec, pubKey)
}

// CreateDIDKeyByCode 根据 multicode，pubKey 构建 DID
func CreateDIDKeyByCode(code uint64, pubKey []byte) (string, string) {
	methodID := KeyFingerprint(code, pubKey)
	didKey := fmt.Sprintf("did:key:%s", methodID)
	keyID := fmt.Sprintf("%s#%s", didKey, methodID)

	return didKey, keyID
}

func CreateDIDKeyByJwk(jsonWebKey *jwk.JWK) (string, string, error) {
	if jsonWebKey == nil {
		return "", "", fmt.Errorf("jsonWebKey is required")
	}

	switch jsonWebKey.Kty {
	case "EC":
		code, curve, err := ecCodeAndCurve(jsonWebKey.Crv)
		if err != nil {
			return "", "", err
		}

		switch key := jsonWebKey.Key.(type) {
		case *ecdsa.PublicKey:
			bytes := elliptic.MarshalCompressed(curve, key.X, key.Y)
			didKey, keyID := CreateDIDKeyByCode(code, bytes)
			return didKey, keyID, nil

		default:
			return "", "", fmt.Errorf("unsupported EC key type: %T", key)
		}

	case "OKP":
		var code uint64
		switch jsonWebKey.Crv {
		case "X25519":
			code = X25519PubKeyMultiCodec
		case "Ed25519":
			code = ED25519PubKeyMultiCodec
		}

		switch key := jsonWebKey.Key.(type) {
		case ed25519.PublicKey:
			didKey, keyID := CreateDIDKey(key)
			return didKey, keyID, nil

		case []byte:
			didKey, keyID := CreateDIDKeyByCode(code, key)
			return didKey, keyID, nil

		default:
			return "", "", fmt.Errorf("unsupported OKP key type: %T", key)
		}

	default:
		return "", "", fmt.Errorf("unsupported kty %s", jsonWebKey.Kty)
	}
}

func ecCodeAndCurve(ecCurve string) (uint64, elliptic.Curve, error) {
	var (
		curve elliptic.Curve
		code  uint64
	)

	switch ecCurve {
	case elliptic.P256().Params().Name, "NIST_P256":
		curve = elliptic.P256()
		code = P256PubKeyMultiCodec
	case elliptic.P384().Params().Name, "NIST_P384":
		curve = elliptic.P384()
		code = P384PubKeyMultiCodec
	case elliptic.P521().Params().Name, "NIST_P521":
		curve = elliptic.P521()
		code = P521PubKeyMultiCodec
	default:
		return 0, nil, fmt.Errorf("unsupported elliptic curve: %s", ecCurve)
	}

	return code, curve, nil
}

func KeyFingerprint(code uint64, pubKeyValue []byte) string {
	multicodecValue := multicodec(code)
	mcLength := len(multicodecValue)
	buf := make([]uint8, mcLength+len(pubKeyValue))
	// 写入编码类型
	copy(buf, multicodecValue)
	// 写入公钥
	copy(buf[mcLength:], pubKeyValue)

	// base58 编码
	return fmt.Sprintf("z%s", base58.Encode(buf))
}

// multicodec 将 code 转成一个可变长整数
func multicodec(code uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	bw := binary.PutUvarint(buf, code)

	return buf[:bw]
}

func PubKeyFromFingerprint(fingerprint string) ([]byte, uint64, error) {
	const maxMultiCodecBytes = 9

	if len(fingerprint) < 2 || fingerprint[0] != 'z' {
		return nil, 0, errors.New("unknown key encoding")
	}

	mc := base58.Decode(fingerprint[1:])
	code, br := binary.Uvarint(mc)
	if br == 0 {
		return nil, 0, errors.New("unknown key encoding")
	}

	if br > maxMultiCodecBytes {
		return nil, 0, errors.New("code exceeds maximum size")
	}

	if code == BLS12381g1g2PubKeyMultiCodec {
		if len(mc[br+g1CompressedSize:]) != bls12381G2PublicKeyLen {
			return nil, 0, errors.New("invalid bbs + public key")
		}

		return mc[br+g1CompressedSize:], code, nil
	}

	return mc[br:], code, nil
}

func PubKeyFromDIDKey(didKey string) ([]byte, error) {
	idMethodSpecificID, err := MethodIDFromDIDKey(didKey)
	if err != nil {
		return nil, fmt.Errorf("pubKeyFromDIDKey: MethodIDFromDIDKey: %w", err)
	}

	pubKey, code, err := PubKeyFromFingerprint(idMethodSpecificID)
	if err != nil {
		return nil, err
	}

	switch code {
	case X25519PubKeyMultiCodec, ED25519PubKeyMultiCodec, BLS12381g2PubKeyMultiCodec, BLS12381g1g2PubKeyMultiCodec,
		P256PubKeyMultiCodec, P384PubKeyMultiCodec, P521PubKeyMultiCodec:
		break
	default:
		return nil, fmt.Errorf("pubKeyFromDIDKey: unsupported key multicodec code [0x%x]", code)
	}

	return pubKey, nil
}
