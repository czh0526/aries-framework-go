package aead

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	aescbcpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto"
	aeadpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

func AES128CBCHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(
		subtle.AES128Size,
		subtle.AES128Size,
		subtle.AES128Size,
		commonpb.HashType_SHA256)
}

func AES192CBCHMACSHA384KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(
		subtle.AES192Size,
		subtle.AES192Size,
		subtle.AES192Size,
		commonpb.HashType_SHA256)
}

func AES256CBCHMACSHA384KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(
		subtle.AES256Size,
		subtle.AES192Size,
		subtle.AES192Size,
		commonpb.HashType_SHA256)
}

func AES256CBCHMACSHA512KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate(
		subtle.AES256Size,
		subtle.AES256Size,
		subtle.AES256Size,
		commonpb.HashType_SHA512)
}

func createAESCBCHMACAEADKeyTemplate(
	aesKeySize, hmacKeySize, tagSize uint32,
	hashType commonpb.HashType) *tinkpb.KeyTemplate {

	format := &aeadpb.AesCbcHmacAeadKeyFormat{
		AesCbcKeyFormat: &aescbcpb.AesCbcKeyFormat{
			KeySize: aesKeySize,
		},
		HmacKeyFormat: &hmacpb.HmacKeyFormat{
			Params:  &hmacpb.HmacParams{Hash: hashType, TagSize: tagSize},
			KeySize: hmacKeySize,
		},
	}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		panic("failed to marshal CBC+HMAC AEAD key format proto")
	}

	return &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          aesCBCHMACAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}
}
