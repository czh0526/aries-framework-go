package ecdh

import (
	"errors"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	nistpECDHKWPublicKeyVersion = 0
	nistpECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
)

var errInvalidNISPPECDHKWPublicKey = errors.New("invalid NIST P-ECDH public key")

type nistPECDHKWPublicKeyManager struct{}

func (n nistPECDHKWPublicKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPublicKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPublicKeyManager) TypeURL() string {
	//TODO implement me
	panic("implement me")
}

func (n nistPECDHKWPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	//TODO implement me
	panic("implement me")
}

var _ registry.KeyManager = (*nistPECDHKWPublicKeyManager)(nil)
