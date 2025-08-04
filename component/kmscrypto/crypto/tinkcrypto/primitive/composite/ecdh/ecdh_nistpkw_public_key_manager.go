package ecdh

import (
	"crypto/elliptic"
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
	nistpECDHKWPublicKeyVersion = 0
	nistpECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
)

var errInvalidNISTPECDHKWPublicKey = errors.New("invalid NIST P-ECDH public key")

type nistPECDHKWPublicKeyManager struct{}

func (km *nistPECDHKWPublicKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidNISTPECDHKWPublicKey
	}

	ecdhPubKey := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(serializedKey, ecdhPubKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPublicKey
	}

	_, err = km.validateKey(ecdhPubKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPublicKey
	}

	rEnc, err := composite.NewRegisterCompositeAEADEncHelper(ecdhPubKey.Params.EncParams.AeadEnc)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_public_key_manager: NewRegisterCompositeAEADHelper failed: %w", err)
	}

	return subtle.NewECDHAEADCompositeCrypto(rEnc, ecdhPubKey.Params.EncParams.CEK), nil
}

func (km *nistPECDHKWPublicKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errors.New("nistpkw_ecdh_public_key_manager: NewKey not implemented")
}

func (km *nistPECDHKWPublicKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (km *nistPECDHKWPublicKeyManager) TypeURL() string {
	return nistpECDHKWPublicKeyTypeURL
}

func (km *nistPECDHKWPublicKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errors.New("nistpkw_ecdh_public_key_manager: NewKeyData not implemented")
}

func (km *nistPECDHKWPublicKeyManager) validateKey(key *ecdhpb.EcdhAeadPublicKey) (elliptic.Curve, error) {
	err := keyset.ValidateKeyVersion(key.Version, nistpECDHKWPublicKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_public_key_manager: invalid key version: %w", err)
	}

	return validateKeyFormat(key.Params)
}

var _ registry.KeyManager = (*nistPECDHKWPublicKeyManager)(nil)

func newECDHNISTPAESPublicKeyManager() *nistPECDHKWPublicKeyManager {
	return new(nistPECDHKWPublicKeyManager)
}
