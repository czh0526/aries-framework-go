package secp256k1

import (
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

type secp256k1VerifierKeyManager struct {
}

func (s secp256k1VerifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1VerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1VerifierKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1VerifierKeyManager) TypeURL() string {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1VerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

func newSecp256K1VerifierKeyManager() *secp256k1VerifierKeyManager {
	return new(secp256k1VerifierKeyManager)
}
