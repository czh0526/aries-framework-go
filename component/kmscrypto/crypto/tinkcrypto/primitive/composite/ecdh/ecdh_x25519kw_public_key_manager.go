package ecdh

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh/subtle"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	x25519ECDHKWPublicKeyVersion = 0
	x25519ECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
)

var errInvalidx25519ECDHKWPublicKey = errors.New("x25519kw_ecdh_public_key_manager: invalid key")

type x25519ECDHKWPublicKeyManager struct{}

func (km *x25519ECDHKWPublicKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidx25519ECDHKWPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPublicKey
	}

	err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidx25519ECDHKWPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("x25519_ecdh_public_key_manager: NewRegisterCompositeAEADEncHelper failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeCrypto(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

func (km *x25519ECDHKWPublicKeyManager) NewKey(serializedKey []byte) (proto.Message, error) {
	return nil, errors.New("x25519kw_ecdh_public_key_manager: NewKey not implemented")
}

func (km *x25519ECDHKWPublicKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (km *x25519ECDHKWPublicKeyManager) TypeURL() string {
	return x25519ECDHKWPublicKeyTypeURL
}

func (km *x25519ECDHKWPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("x25519kw_ecdh_public_key_manager: NewKeyData not implemented")
}

func (km *x25519ECDHKWPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) error {
	err := keyset.ValidateKeyVersion(key.Version, x25519ECDHKWPublicKeyVersion)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_public_key_manager: invalid key version: %w", err)
	}

	return validateKeyXChaChaFormat(key.Params)
}

var _ registry.KeyManager = (*x25519ECDHKWPublicKeyManager)(nil)

func newX25519ECDHKWPublicKeyManager() *x25519ECDHKWPublicKeyManager {
	return new(x25519ECDHKWPublicKeyManager)
}
