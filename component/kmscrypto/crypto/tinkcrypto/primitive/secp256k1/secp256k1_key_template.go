package secp256k1

import (
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

func DERKeyTemplate() (*tinkpb.KeyTemplate, error) {
	return createECDSAKeyTemplate(
		commonpb.HashType_SHA256,
		secp256k1pb.)
}