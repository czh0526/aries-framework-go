package secp256k1

import (
	"errors"
	"fmt"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	secp256k1SignerKeyVersion = 0
	secp256k1SignerTypeURL    = "type.googleapis.com/google.crypto.tink.secp256k1PrivateKey"
)

var (
	errInvalidSECP256K1SignKey       = errors.New("secp256k1_signer_key_manager: invalid key")
	errInvalidSECP256K1SignKeyFormat = errors.New("secp256k1_signer_key_manager: invalid key format")
)

type secp256k1SignerKeyManager struct {
}

func (km *secp256k1SignerKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidSECP256K1SignKey
	}

	key := new(secp256k1pb.Secp256K1PrivateKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidSECP256K1SignKey
	}

	if err := km.validateKey(key); err != nil {
		return nil, err
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.PublicKey.Params)
	ret, err := subtleSignature.NewSecp256K1Signer(hash, curve, encoding, key.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_signer_key_manager: %w", err)
	}

	return ret, nil
}

func (km secp256k1SignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	//TODO implement me
	panic("implement me")
}

func (km secp256k1SignerKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (km secp256k1SignerKeyManager) TypeURL() string {
	//TODO implement me
	panic("implement me")
}

func (km secp256k1SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

func (km *secp256k1SignerKeyManager) validateKey(key *secp256k1pb.Secp256K1PrivateKey) error {
	return nil
}

func newSecp256K2SignerKeyManager() *secp256k1SignerKeyManager {
	return new(secp256k1SignerKeyManager)
}

func getSecp256K1ParamNames(params *secp256k1pb.Secp256K1Params) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.HashType)]
	curveName := secp256k1pb.BitcoinCurveType_name[int32(params.Curve)]
	encodingName := secp256k1pb.Secp256K1SignatureEncoding_name[int32(params.Encoding)]

	return hashName, curveName, encodingName
}
