package localkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	secp256k1subtle "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"google.golang.org/protobuf/proto"
)

func PublicKeyBytesToHandle(pubKey []byte, kt spikms.KeyType, opts ...spikms.KeyOpts) (*keyset.Handle, error) {
	if len(pubKey) == 0 {
		return nil, fmt.Errorf("pubKey is empty")
	}

	marshalledKey, tURL, err := getMarshalledProtoKeyAndKeyURL(pubKey, kt, opts...)
	if err != nil {
		return nil, fmt.Errorf("error getting marshalled proto key: %w", err)
	}

	ks := newKeySet(tURL, marshalledKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC)

	memReader := &keyset.MemReaderWriter{Keyset: ks}
	parsedHandle, err := insecurecleartextkeyset.Read(memReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create key handle: %w", err)
	}

	return parsedHandle, nil
}

func getMarshalledProtoKeyAndKeyURL(pubKey []byte, kt spikms.KeyType, opts ...spikms.KeyOpts) ([]byte, string, error) {
	var (
		tURL     string
		keyValue []byte
		err      error
	)

	switch kt {
	case spikms.ECDSAP256TypeDER:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSADERKey(
			pubKey,
			"NIST_P256",
			commonpb.EllipticCurveType_NIST_P256,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}

	case spikms.ECDSAP384TypeDER:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSADERKey(
			pubKey,
			"NIST_P384",
			commonpb.EllipticCurveType_NIST_P384,
			commonpb.HashType_SHA384)
		if err != nil {
			return nil, "", err
		}

	case spikms.ECDSAP521TypeDER:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSADERKey(
			pubKey,
			"NIST_P521",
			commonpb.EllipticCurveType_NIST_P521,
			commonpb.HashType_SHA512)
		if err != nil {
			return nil, "", err
		}

	case spikms.ECDSAP256TypeIEEEP1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEEP1363Key(
			pubKey,
			"NIST_P256",
			commonpb.EllipticCurveType_NIST_P256,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}

	case spikms.ECDSAP384TypeIEEEP1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEEP1363Key(
			pubKey,
			"NIST_P384",
			commonpb.EllipticCurveType_NIST_P384,
			commonpb.HashType_SHA384)
		if err != nil {
			return nil, "", err
		}

	case spikms.ECDSAP521TypeIEEEP1363:
		tURL = ecdsaVerifierTypeURL

		keyValue, err = getMarshalledECDSAIEEEP1363Key(
			pubKey,
			"NIST_P521",
			commonpb.EllipticCurveType_NIST_P521,
			commonpb.HashType_SHA512)
		if err != nil {
			return nil, "", err
		}

	case spikms.ED25519Type:
		tURL = ed25519VerifierTypeURL

		pubKeyProto := new(ed25519pb.Ed25519PublicKey)
		pubKeyProto.Version = 0
		pubKeyProto.KeyValue = make([]byte, len(pubKey))
		copy(pubKeyProto.KeyValue, pubKey)

	case spikms.ECDSASecp256k1DER:
		tURL = secp256k1VerifierTypeURL

		keyValue, err = getMarshalledECDSASecp256K1DERKey(
			pubKey,
			"SECP256K1",
			secp256k1pb.BitcoinCurveType_SECP256K1,
			commonpb.HashType_SHA256)
		if err != nil {
			return nil, "", err
		}

	case spikms.ECDSASecp256k1TypeIEEEP1363:
		tURL = secp256k1VerifierTypeURL

		keyValue, err = getMarshalledECDSASecp256K1IEEEP1363Key(
			pubKey,
			"SECP256K1",
			secp256k1pb.BitcoinCurveType_SECP256K1,
			commonpb.HashType_SHA256)

	case spikms.BLS12381G2Type:
		return nil, "", fmt.Errorf("[implement me] key type: %s", kt)

	case spikms.CLCredDefType:
		return nil, "", fmt.Errorf("[implement me] key type: %s", kt)

	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", kt)
	}
	return keyValue, tURL, nil
}

func getMarshalledECDSADERKey(marshaledPubKey []byte, curveName string, curveType commonpb.EllipticCurveType,
	hashType commonpb.HashType) ([]byte, error) {

	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	pubKey, err := x509.ParsePKIXPublicKey(marshaledPubKey)
	if err != nil {
		return nil, err
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key reader: not an ecdsa public key")
	}

	params := &ecdsapb.EcdsaParams{
		Curve:    curveType,
		Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		HashType: hashType,
	}

	return getMarshalledECDSAKey(ecPubKey, params)
}

func getMarshalledECDSASecp256K1DERKey(marshaledPubKey []byte, curveName string, curveType secp256k1pb.BitcoinCurveType,
	hashType commonpb.HashType) ([]byte, error) {
	curve := secp256k1subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	pubKey, err := x509.ParsePKIXPublicKey(marshaledPubKey)
	if err != nil {
		return nil, err
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key reader: not an ecdsa public key")
	}

	params := &secp256k1pb.Secp256K1Params{
		Curve:    curveType,
		Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
		HashType: hashType,
	}

	return getMarshalledSecp256Key(ecPubKey, params)
}

func getMarshalledECDSAIEEEP1363Key(marshaledPubKey []byte, curveName string, curveType commonpb.EllipticCurveType,
	hashType commonpb.HashType) ([]byte, error) {
	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	x, y := elliptic.Unmarshal(curve, marshaledPubKey)
	if x == nil || y == nil {
		return nil, fmt.Errorf("faild to unmarshal public ecdsa key")
	}

	params := &ecdsapb.EcdsaParams{
		Curve:    curveType,
		Encoding: ecdsapb.EcdsaSignatureEncoding_IEEE_P1363,
		HashType: hashType,
	}

	return getMarshalledECDSAKey(&ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: curve,
	}, params)
}

func getMarshalledECDSASecp256K1IEEEP1363Key(marshaledPubKey []byte, curveName string, curveType secp256k1pb.BitcoinCurveType,
	hashType commonpb.HashType) ([]byte, error) {
	curve := secp256k1subtle.GetCurve(curveName)
	if curve == nil {
		return nil, fmt.Errorf("undefined curve")
	}

	x, y := elliptic.Unmarshal(curve, marshaledPubKey)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to unmarshal public ecdsa key")
	}

	params := &secp256k1pb.Secp256K1Params{
		Curve:    curveType,
		Encoding: secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363,
		HashType: hashType,
	}

	return getMarshalledSecp256Key(&ecdsa.PublicKey{
		X:     x,
		Y:     y,
		Curve: curve,
	}, params)
}

func getMarshalledECDSAKey(ecPubKey *ecdsa.PublicKey, params *ecdsapb.EcdsaParams) ([]byte, error) {
	return proto.Marshal(newProtoECDSAPublicKey(ecPubKey, params))
}

func getMarshalledSecp256Key(ecPubKey *ecdsa.PublicKey, params *secp256k1pb.Secp256K1Params) ([]byte, error) {
	return proto.Marshal(newProtoSecp256K1PublicKey(ecPubKey, params))
}

func newProtoECDSAPublicKey(ecPubKey *ecdsa.PublicKey, params *ecdsapb.EcdsaParams) *ecdsapb.EcdsaPublicKey {
	return &ecdsapb.EcdsaPublicKey{
		Version: 0,
		X:       ecPubKey.X.Bytes(),
		Y:       ecPubKey.Y.Bytes(),
		Params:  params,
	}
}

func newProtoSecp256K1PublicKey(ecPubKey *ecdsa.PublicKey,
	params *secp256k1pb.Secp256K1Params) *secp256k1pb.Secp256K1PublicKey {
	return &secp256k1pb.Secp256K1PublicKey{
		Version: 0,
		X:       ecPubKey.X.Bytes(),
		Y:       ecPubKey.Y.Bytes(),
		Params:  params,
	}
}

func newKeySet(tURL string, marshalledKey []byte, keyMaterialType tinkpb.KeyData_KeyMaterialType) *tinkpb.Keyset {
	keyData := &tinkpb.KeyData{
		TypeUrl:         tURL,
		Value:           marshalledKey,
		KeyMaterialType: keyMaterialType,
	}

	return &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		PrimaryKeyId: 1,
	}
}
