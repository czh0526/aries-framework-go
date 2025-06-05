package aead

import (
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func AES128CBCHMACSHA256KeyTemplate() *tinkpb.KeyTemplate {
	return createAESCBCHMACAEADKeyTemplate()
}

func createAESCBCHMACAEADKeyTemplate(
	aesKeySize, hmacKeySize, tagSize uint32,
	hashType commonpb.HashType) *tinkpb.KeyTemplate {

	format := &aeadpb.Aes
}
