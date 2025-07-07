package ecdh

import (
	"errors"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	nistpECDHKWPrivateKeyVersion = 0
	nistpECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
)

var (
	errInvalidNISTPECDHKWPrivateKey      = errors.New("nistpkw_ecdh_private_key_manager: invalid key")
	errInvalidNISTPECDHWPrivateKeyFormat = errors.New("nistpkw_ecdh_private_key_manager: invalid key format")
)

type nistPECDHKWPrivateKeyManager struct{}

func (n nistPECDHKWPrivateKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPrivateKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPrivateKeyManager) TypeURL() string {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPrivateKeyManager) PublicKeyData(serializedKey []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

var _ registry.PrivateKeyManager = (*nistPECDHKWPrivateKeyManager)(nil)
