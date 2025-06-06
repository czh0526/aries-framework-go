package localkms

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/mac"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"google.golang.org/protobuf/proto"
)

func keyTemplate(keyType spikms.KeyType, _ ...spikms.KeyOpts) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case spikms.AES128GCMType:
		return aead.AES128GCMKeyTemplate(), nil
	case spikms.AES256GCMNoPrefix:
		return aead.AES256GCMNoPrefixKeyTemplate(), nil
	case spikms.AES256GCMType:
		return aead.AES256GCMKeyTemplate(), nil
	case spikms.ChaCha20Poly1305Type:
		return aead.ChaCha20Poly1305KeyTemplate(), nil
	case spikms.XChaCha20Poly1305Type:
		return aead.XChaCha20Poly1305KeyTemplate(), nil
	case spikms.ECDSAP256TypeDER:
		return signature.ECDSAP256KeyWithoutPrefixTemplate(), nil
	case spikms.ECDSAP384TypeDER:
		// Since Tink's signature.ECDSAP384KeyWithoutPrefixTemplate() uses SHA_512 as the hashing function during
		// signature/verification, the kms type must explicitly use SHA_384 just as IEEEP384 key template below.
		// For this reason, the KMS cannot use Tink's `signature.ECDSAP384KeyWithoutPrefixTemplate()` template here.
		return createECDSAKeyTemplate(
			ecdsapb.EcdsaSignatureEncoding_DER,
			commonpb.HashType_SHA384,
			commonpb.EllipticCurveType_NIST_P384,
		), nil
	case spikms.ECDSAP521TypeDER:
		return signature.ECDSAP521KeyWithoutPrefixTemplate(), nil
	case spikms.ECDSAP256TypeIEEEP1363:
		return createECDSAIEE1363KeyTemplate(
			commonpb.HashType_SHA256, commonpb.EllipticCurveType_NIST_P256), nil
	case spikms.ECDSAP384TypeIEEEP1363:
		return createECDSAIEE1363KeyTemplate(
			commonpb.HashType_SHA384, commonpb.EllipticCurveType_NIST_P384), nil
	case spikms.ECDSAP521TypeIEEEP1363:
		return createECDSAIEE1363KeyTemplate(
			commonpb.HashType_SHA512, commonpb.EllipticCurveType_NIST_P521), nil
	case spikms.ED25519Type:
		return signature.ED25519KeyWithoutPrefixTemplate(), nil
	case spikms.HMACSHA256Tag256Type:
		return mac.HMACSHA256Tag256KeyTemplate(), nil
	case spikms.NISTP256ECDHKWType:
		return ecdh.NISTP256ECDHKWKeyTemplate(), nil
	case spikms.NISTP384ECDHKWType:
		return ecdh.NISTP384ECDHKWKeyTemplate(), nil
	case spikms.NISTP521ECDHKWType:
		return ecdh.NISTP521ECDHKWKeyTemplate(), nil
	case spikms.X25519ECDHKWType:
		return ecdh.X25519ECDHKWKeyTemplate(), nil
	case spikms.BLS12381G2Type:
		return nil, fmt.Errorf("getKeyTemplate: key type `BLS+` is not supported")
	case spikms.ECDSASecp256k1DER:
		return secp256k1.D
	case spikms.ECDSASecp256k1TypeIEEEP1363:
	default:
		return nil, fmt.Errorf("getKeyTemplate: key type `%s` unrecognized", keyType)
	}
}

func createECDSAIEE1363KeyTemplate(hashType commonpb.HashType, curve commonpb.EllipticCurveType) *tinkpb.KeyTemplate {
	return createECDSAKeyTemplate(ecdsapb.EcdsaSignatureEncoding_IEEE_P1363, hashType, curve)
}

func createECDSAKeyTemplate(sigEncoding ecdsapb.EcdsaSignatureEncoding, hashType commonpb.HashType,
	curve commonpb.EllipticCurveType) *tinkpb.KeyTemplate {

	params := &ecdsapb.EcdsaParams{
		HashType: hashType,
		Curve:    curve,
		Encoding: sigEncoding,
	}

	format := &ecdsapb.EcdsaKeyFormat{
		Params: params,
	}
	serializedFormat, _ := proto.Marshal(format)

	return &tinkpb.KeyTemplate{
		TypeUrl:          ecdsaPrivateKeyTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
