package secp256k1

import (
	"errors"
	"fmt"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	secp256k1VerifierKeyVersion = 0
	secp256k1VerifierKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.Secp256k1VerifierKey"
)

var (
	errInvalidsecp256k1VerifierKey     = errors.New("secp256k1_verifier_key_manager: invalid key")
	errSecp256k1VerifierNotImplemented = errors.New("secp256k1_verifier_key_manager: not implemented")
)

type secp256k1VerifierKeyManager struct {
}

func (km *secp256k1VerifierKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidsecp256k1VerifierKey
	}

	key := new(secp256k1pb.Secp256K1PublicKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidsecp256k1VerifierKey
	}

	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("secp256k1_verifier_key_manager: %v", err)
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.Params)

	ret, err := subtle.NewSecp256K1Verifier(hash, curve, encoding, key.X, key.Y)
	if err != nil {
		return nil, fmt.Errorf("secp256k1_verifier_key_manager: invalid key: %v", err)
	}
	return ret, nil
}

func (km *secp256k1VerifierKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	return nil, errSecp256k1VerifierNotImplemented
}

func (km *secp256k1VerifierKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	return nil, errSecp256k1VerifierNotImplemented
}

func (km *secp256k1VerifierKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == secp256k1VerifierKeyTypeURL
}

func (km *secp256k1VerifierKeyManager) TypeURL() string {
	return secp256k1VerifierKeyTypeURL
}

func (km *secp256k1VerifierKeyManager) validateKey(key *secp256k1pb.Secp256K1PublicKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, secp256k1VerifierKeyVersion); err != nil {
		return fmt.Errorf("secp256k1_verifier_key_manager: %v", err)
	}

	hash, curve, encoding := getSecp256K1ParamNames(key.Params)
	return ValidateSecp256K1Params(hash, curve, encoding)
}

func newSecp256K1VerifierKeyManager() *secp256k1VerifierKeyManager {
	return new(secp256k1VerifierKeyManager)
}
