package secp256k1

import (
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	secp256k1SignerKeyVersion = 0
	secp256k1SignerTypeURL    = "type.googleapis.com/google.crypto.tink.secp256k1PrivateKey"
)

type secp256k1SignerKeyManager struct {
}

func (s secp256k1SignerKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1SignerKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1SignerKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1SignerKeyManager) TypeURL() string {
	//TODO implement me
	panic("implement me")
}

func (s secp256k1SignerKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

func newSecp256K2SignerKeyManager() *secp256k1SignerKeyManager {
	return new(secp256k1SignerKeyManager)
}
