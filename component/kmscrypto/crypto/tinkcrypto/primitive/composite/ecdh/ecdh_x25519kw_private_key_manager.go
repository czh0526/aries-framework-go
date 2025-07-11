package ecdh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	x25519ECDHKWPrivateKeyVersion = 0
	x25519ECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"
)

var (
	errInvalidX25519ECDHKWPrivateKey       = errors.New("x25519kw_ecdh_private_key_manager: invalid key")
	errInvalidX25519ECDHKWPrivateKeyFormat = errors.New("x25519kw_ecdh_private_key_manager: invalid key format")
)

type x25519ECDHKWPrivateKeyManager struct{}

func (km *x25519ECDHKWPrivateKeyManager) PublicKeyData(serializedKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, privKey)
	if err != nil {
		return nil, errInvalidX25519ECDHKWPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidX25519ECDHKWPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         x25519ECDHKWPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

func (km *x25519ECDHKWPrivateKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (km *x25519ECDHKWPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidX25519ECDHKWPrivateKeyFormat
	}

	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)
	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidX25519ECDHKWPrivateKeyFormat
	}

	err = validateKeyXChaChaFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidX25519ECDHKWPrivateKeyFormat
	}

	if keyFormat.Params.EncParams.CEK != nil {
		return &ecdhpb.EcdhAeadPrivateKey{
			Version:  x25519ECDHKWPrivateKeyVersion,
			KeyValue: []byte{},
			PublicKey: &ecdhpb.EcdhAeadPublicKey{
				Version: x25519ECDHKWPrivateKeyVersion,
				Params:  keyFormat.Params,
				X:       []byte{},
			},
		}, nil
	}

	pub, pvt, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	x25519Pub, err := cryptoutil.PublicEd25519toCurve25519(pub)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: Convert to X25519 pub key failed: %w", err)
	}

	x25519Pvt, err := cryptoutil.SecretEd25519toCurve25519(pvt)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: Convert to X25519 priv key failed: %w", err)
	}

	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  x25519ECDHKWPrivateKeyVersion,
		KeyValue: x25519Pvt,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: x25519ECDHKWPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       x25519Pub,
		},
	}, nil
}

func (km *x25519ECDHKWPrivateKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (km *x25519ECDHKWPrivateKeyManager) TypeURL() string {
	return x25519ECDHKWPrivateKeyTypeURL
}

func (km *x25519ECDHKWPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("x25519kw_ecdh_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         x25519ECDHKWPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

var _ registry.PrivateKeyManager = (*x25519ECDHKWPrivateKeyManager)(nil)

func newX25519ECDHKWPrivateKeyManager() *x25519ECDHKWPrivateKeyManager {
	return new(x25519ECDHKWPrivateKeyManager)
}

func validateKeyXChaChaFormat(params *ecdhpb.EcdhAeadParams) error {
	var err error

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: GetKeyManager error: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: NewKeyData error: %w", err)
	}

	if params.KwParams.KeyType.String() != ecdhpb.KeyType_OKP.String() {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: invalid key type: %v", params.KwParams.KeyType)
	}

	if params.EncParams.CEK == nil &&
		params.KwParams.CurveType.String() != commonpb.EllipticCurveType_CURVE25519.String() {
		return fmt.Errorf("x25519kw_ecdh_private_key_manager: invalid curve: %v", params.KwParams.CurveType)
	}

	return nil
}
