package kmsdidkey

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	comp_crypto "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
)

var keyTypeCodecs = map[spikms.KeyType]uint64{
	// signing keys
	spikms.ED25519Type:            fingerprint.ED25519PubKeyMultiCodec,
	spikms.BLS12381G2Type:         fingerprint.BLS12381g2PubKeyMultiCodec,
	spikms.ECDSAP256TypeIEEEP1363: fingerprint.P256PubKeyMultiCodec,
	spikms.ECDSAP256DER:           fingerprint.P256PubKeyMultiCodec,
	spikms.ECDSAP384TypeIEEEP1363: fingerprint.P384PubKeyMultiCodec,
	spikms.ECDSAP384DER:           fingerprint.P384PubKeyMultiCodec,
	spikms.ECDSAP521TypeIEEEP1363: fingerprint.P521PubKeyMultiCodec,
	spikms.ECDSAP521DER:           fingerprint.P521PubKeyMultiCodec,

	// encryption keys
	spikms.X25519ECDHKWType:   fingerprint.X25519PubKeyMultiCodec,
	spikms.NISTP256ECDHKWType: fingerprint.P256PubKeyMultiCodec,
	spikms.NISTP384ECDHKWType: fingerprint.P384PubKeyMultiCodec,
	spikms.NISTP521ECDHKWType: fingerprint.P521PubKeyMultiCodec,
}

func BuildDIDKeyByKeyType(pubKeyBytes []byte, keyType spikms.KeyType) (string, error) {
	switch keyType {
	case spikms.X25519ECDHKW:
		pubKey := &spicrypto.PublicKey{}
		err := json.Unmarshal(pubKeyBytes, pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDKeyByKMSKeyType unmarshal key failed, type = %v, err = %w", keyType, err)
		}

		pubKeyBytes = make([]byte, len(pubKey.X))
		copy(pubKeyBytes, pubKey.X)

	case spikms.NISTP256ECDHKWType, spikms.NISTP384ECDHKWType, spikms.NISTP521ECDHKWType:
		pubKey := &spicrypto.PublicKey{}
		err := json.Unmarshal(pubKeyBytes, pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDKeyByKMSKeyType unmarshal key failed, type = %v, err = %w", keyType, err)
		}

		ecKey, err := comp_crypto.ToECKey(pubKey)
		if err != nil {
			return "", fmt.Errorf("buildDIDKeyByKMSKeyType unmarshal key failed, type = %v, err = %w", keyType, err)
		}

		pubKeyBytes = elliptic.MarshalCompressed(ecKey.Curve, ecKey.X, ecKey.Y)
	}

	if codec, ok := keyTypeCodecs[keyType]; ok {
		didKey, _ := fingerprint.CreateDIDKeyByCode(codec, pubKeyBytes)
		return didKey, nil
	}

	return "", fmt.Errorf("keyType '%s' does not have a multi-base codec", keyType)
}

// EncryptionPubKeyFromDIDKey 根据 did keyId 计算出公钥对象，包括：
// 1）椭圆曲线类型
// 2）公钥点X坐标
// 3）公钥点Y坐标
// 4) 公钥类型
func EncryptionPubKeyFromDIDKey(didKey string) (*spicrypto.PublicKey, error) {
	pubKey, code, err := extractRawKey(didKey)
	if err != nil {
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
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
		var edKID string

		kmtKT = spikms.ED25519Type
		pubEDKey := &spicrypto.PublicKey{
			X:     pubKey,
			Curve: "Ed25519",
			Type:  "OKP",
		}

		edKID, err = jwkkid.CreateKID(pubKey, kmtKT)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
		}

		pubEDKey.KID = edKID
		return pubEDKey, nil

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
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
		}

		xKID, err = jwkkid.CreateKID(mPubXKey, kmtKT)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %w", err)
		}

		pubXKey.KID = xKID
		return pubXKey, nil

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
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey failed: err = %w", err)
	}

	return &spicrypto.PublicKey{
		KID:   kid,
		X:     x,
		Y:     y,
		Curve: crv,
		Type:  kt,
	}, nil
}

// extractRawKey 将 keyID 分解成 codec + public key
func extractRawKey(didKey string) ([]byte, uint64, error) {
	idMethodSpecificID, err := fingerprint.MethodIDFromDIDKey(didKey)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: fingerprint.MethodIDFromDIDKey failure: %w", err)
	}

	pubKey, code, err := fingerprint.PubKeyFromFingerprint(idMethodSpecificID)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: fingerprint.PubKeyFromFingerprint failure: %w", err)
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
