package ecdh

import (
	cbcaead "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

type AEADAlg int

const (
	AES256GCM = iota + 1
	XC20P
	AES128CBCHMACSHA256
	AES192CBCHMACSHA384
	AES256CBCHMACSHA384
	AES256CBCHMACSHA521
)

func NISTP256ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(
		true, AES256GCM, commonpb.EllipticCurveType_NIST_P256, nil)
}

func NISTP384ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(
		true, AES256GCM, commonpb.EllipticCurveType_NIST_P384, nil)
}

func NISTP521ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(
		true, AES256GCM, commonpb.EllipticCurveType_NIST_P521, nil)
}

func X25519ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate(
		false, XC20P, commonpb.EllipticCurveType_CURVE25519, nil)
}

func createKeyTemplate(nistpKW bool, encAlg AEADAlg, c commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	typeURL, keyType, encTemplate := getTypeParams(nistpKW, encAlg, cek)

	format := &ecdhpb.EcdhAeadKeyFormat{
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: c,
				KeyType:   keyType,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encTemplate,
				CEK:     cek,
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal EcdhAeadKeyFormat proto")
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          typeURL,
		Value:            serializedFormat,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}

func getTypeParams(nistpKW bool, encAlg AEADAlg, cek []byte) (string, ecdhpb.KeyType, *tinkpb.KeyTemplate) {
	var (
		keyTemplate *tinkpb.KeyTemplate
		twoKeys     = 2
	)

	switch encAlg {
	case AES256GCM:
		keyTemplate = aead.AES256GCMKeyTemplate()
	case AES128CBCHMACSHA256, AES192CBCHMACSHA384, AES256CBCHMACSHA384, AES256CBCHMACSHA521:
		switch len(cek) {
		case subtle.AES128Size * twoKeys:
			keyTemplate = cbcaead.AES128CBCHMACSHA256KeyTemplate()
		case subtle.AES192Size * twoKeys:
			keyTemplate = cbcaead.AES192CBCHMACSHA384KeyTemplate()
		case subtle.AES256Size + subtle.AES192Size:
			keyTemplate = cbcaead.AES256CBCHMACSHA384KeyTemplate()
		case subtle.AES256Size * twoKeys:
			keyTemplate = cbcaead.AES256CBCHMACSHA512KeyTemplate()
		}
	case XC20P:
		keyTemplate = aead.XChaCha20Poly1305KeyTemplate()
	}

	if nistpKW {
		return nistpECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_EC, keyTemplate
	}

	return x25519ECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_OKP, keyTemplate
}
