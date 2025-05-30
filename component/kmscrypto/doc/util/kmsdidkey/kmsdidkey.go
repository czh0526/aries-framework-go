package kmsdidkey

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
)

// EncryptionPubKeyFromDIDKey 根据 did keyId 获取公钥
func EncryptionPubKeyFromDIDKey(didKey string) (*spicrypto.PublicKey, error) {
	pubKey, code, err := extractRawKey(didKey)
	if err != nil {
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %v", err)
	}

	var (
		crv   string
		kmtKT spikms.KeyType
		kt    string
		x     []byte
		y     []byte
	)

	switch code {
	case fingerprint.ED25519PubKeyMultiCodec:
	case fingerprint.X25519PubKeyMultiCodec:
		var (
			mPubXKey []byte
			xKID     string
		)

		kmtKT = spikms.X25519ECDHKWType
		pubXKey := &spicrypto.PublicKey{
			X:     pubKey,
			Curve: "X25519",
			Type:  "OKP",
		}

		mPubXKey, err = json.Marshal(pubXKey)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %v", err)
		}

		xKID, err = jwkkid.CreateKID(mPubXKey, kmtKT)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %v", err)
		}

		pubXKey.KID = xKID

	case fingerprint.P256PubKeyMultiCodec:
		kmtKT = spikms.ECDSAP256TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P256(), pubKey)

	case fingerprint.P384PubKeyMultiCodec:
		kmtKT = spikms.ECDSAP384TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P384(), pubKey)

	case fingerprint.P521PubKeyMultiCodec:
		kmtKT = spikms.ECDSAP521TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P521(), pubKey)

	default:
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: unsupported key multicodec code [0x%x]", code)
	}

	kid, err := jwkkid.CreateKID(pubKey, kmtKT)
	if err != nil {
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey failed: err = %v", err)
	}

	return &spicrypto.PublicKey{
		KID:   kid,
		X:     x,
		Y:     y,
		Curve: crv,
		Type:  kt,
	}, nil
}

func extractRawKey(didKey string) ([]byte, uint64, error) {
	idMethodSpecificID, err := fingerprint.MethodIDFromDIDKey(didKey)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: fingerprint.MethodIDFromDIDKey failure: %v", err)
	}

	pubKey, code, err := fingerprint.PubKeyFromFingerprint(idMethodSpecificID)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: fingerprint.PubKeyFromFingerprint failure: %v", err)
	}

	return pubKey, code, nil
}

func unmarshalECKey(ecCRV elliptic.Curve, pubKey []byte) (string, []byte, []byte, []byte) {
	var (
		x []byte
		y []byte
	)

	ecCurves := map[elliptic.Curve]string{
		elliptic.P256(): commonpb.EllipticCurveType_NIST_P256.String(),
		elliptic.P384(): commonpb.EllipticCurveType_NIST_P384.String(),
		elliptic.P521(): commonpb.EllipticCurveType_NIST_P521.String(),
	}

	xBig, yBig := elliptic.UnmarshalCompressed(ecCRV, pubKey)
	if xBig != nil && yBig != nil {
		x = xBig.Bytes()
		y = yBig.Bytes()

		pubKey = elliptic.Marshal(ecCRV, xBig, yBig)
	} else {
		// 4 => 标志位，表明是未压缩的公钥坐标
		pubKey = append([]byte{4}, pubKey...)
		xBig, yBig = elliptic.Unmarshal(ecCRV, pubKey)

		x = xBig.Bytes()
		y = yBig.Bytes()
	}

	return ecCurves[ecCRV], x, y, pubKey
}
