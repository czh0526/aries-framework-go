package ecdh

import (
	"errors"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	x25519ECDHKWPublicKeyVersion = 0
	x25519ECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
)

var errInvalidx25519ECDHKWPublicKey = errors.New("x25519kw_ecdh_public_key_manager: invalid key")

type x25519ECDHKWPublicKeyManager struct{}

func (x *x25519ECDHKWPublicKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (x *x25519ECDHKWPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	//TODO implement me
	panic("implement me")
}

func (x *x25519ECDHKWPublicKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (x *x25519ECDHKWPublicKeyManager) TypeURL() string {
	return x25519ECDHKWPublicKeyTypeURL
}

func (x *x25519ECDHKWPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

var _ registry.KeyManager = (*x25519ECDHKWPublicKeyManager)(nil)

func newX25519ECDHKWPublicKeyManager() *x25519ECDHKWPublicKeyManager {
	return new(x25519ECDHKWPublicKeyManager)
}
