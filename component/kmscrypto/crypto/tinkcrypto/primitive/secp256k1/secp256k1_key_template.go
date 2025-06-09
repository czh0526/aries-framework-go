package secp256k1

import (
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

func DERKeyTemplate() (*tinkpb.KeyTemplate, error) {
	return createECDSAKeyTemplate(
		commonpb.HashType_SHA256,
		secp256k1pb.BitcoinCurveType_SECP256K1,
		secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER,
		tinkpb.OutputPrefixType_TINK)
}

func IEEEP1363KeyTemplate() (*tinkpb.KeyTemplate, error) {
	return createECDSAKeyTemplate(
		commonpb.HashType_SHA256,
		secp256k1pb.BitcoinCurveType_SECP256K1,
		secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363,
		tinkpb.OutputPrefixType_TINK)
}

func createECDSAKeyTemplate(hashType commonpb.HashType,
	curve secp256k1pb.BitcoinCurveType, encoding secp256k1pb.Secp256K1SignatureEncoding,
	prefixType tinkpb.OutputPrefixType) (*tinkpb.KeyTemplate, error) {

	params := &secp256k1pb.Secp256K1Params{
		HashType: hashType,
		Curve:    curve,
		Encoding: encoding,
	}

	format := &secp256k1pb.Secp256K1KeyFormat{Params: params}

	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		return nil, err
	}

	return &tinkpb.KeyTemplate{
		TypeUrl:          secp256k1SignerTypeURL,
		Value:            serializedFormat,
		OutputPrefixType: prefixType,
	}, nil
}
