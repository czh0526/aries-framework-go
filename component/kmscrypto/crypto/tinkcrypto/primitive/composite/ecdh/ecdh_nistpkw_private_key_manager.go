package ecdh

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
)

const (
	nistpECDHKWPrivateKeyVersion = 0
	nistpECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
)

var (
	errInvalidNISTPECDHKWPrivateKey       = errors.New("nistpkw_ecdh_private_key_manager: invalid key")
	errInvalidNISTPECDHKWPrivateKeyFormat = errors.New("nistpkw_ecdh_private_key_manager: invalid key format")
)

type nistPECDHKWPrivateKeyManager struct{}

func (km *nistPECDHKWPrivateKeyManager) Primitive(serializedKey []byte) (any, error) {
	//TODO implement me
	panic("implement me")
}

func (km *nistPECDHKWPrivateKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidNISTPECDHKWPrivateKeyFormat
	}

	// 反解析 key params
	keyFormat := new(ecdhpb.EcdhAeadKeyFormat)
	err := proto.Unmarshal(serializedKeyFormat, keyFormat)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKeyFormat
	}

	curve, err := validateKeyFormat(keyFormat.Params)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKeyFormat
	}

	if keyFormat.Params.EncParams.CEK != nil {
		return &ecdhpb.EcdhAeadPrivateKey{
			Version:  nistpECDHKWPrivateKeyVersion,
			KeyValue: []byte{},
			PublicKey: &ecdhpb.EcdhAeadPublicKey{
				Version: nistpECDHKWPrivateKeyVersion,
				Params:  keyFormat.Params,
				X:       []byte{},
				Y:       []byte{},
			},
		}, nil
	}

	// 生成密钥
	pvt, err := hybrid.GenerateECDHKeyPair(curve)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: GenerateECDHKeyPair failed: %w", err)
	}

	// 打包密钥
	return &ecdhpb.EcdhAeadPrivateKey{
		Version:  nistpECDHKWPrivateKeyVersion,
		KeyValue: pvt.D.Bytes(),
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: nistpECDHKWPrivateKeyVersion,
			Params:  keyFormat.Params,
			X:       pvt.PublicKey.Point.X.Bytes(),
			Y:       pvt.PublicKey.Point.Y.Bytes(),
		},
	}, nil
}

func (km *nistPECDHKWPrivateKeyManager) DoesSupport(typeURL string) bool {
	//TODO implement me
	panic("implement me")
}

func (km *nistPECDHKWPrivateKeyManager) TypeURL() string {
	return nistpECDHKWPrivateKeyTypeURL
}

// NewKeyData 构建一个新的 Key
// 参数:  serializedKeyFormat KeyTemplate.Value 中的数据
func (km *nistPECDHKWPrivateKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	// 根据 serializedKeyFormat 中的各个参数，构建新的 Key, 并封装到 proto.Message 中
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: Proto.Marshal failed: %w", err)
	}

	return &tinkpb.KeyData{
		TypeUrl:         nistpECDHKWPrivateKeyTypeURL,
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PRIVATE,
	}, nil
}

func (km *nistPECDHKWPrivateKeyManager) PublicKeyData(serializedKey []byte) (*tinkpb.KeyData, error) {
	privKey := new(ecdhpb.EcdhAeadPrivateKey)

	err := proto.Unmarshal(serializedKey, privKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	serializedPubKey, err := proto.Marshal(privKey.PublicKey)
	if err != nil {
		return nil, errInvalidNISTPECDHKWPrivateKey
	}

	return &tinkpb.KeyData{
		TypeUrl:         nistpECDHKWPublicKeyTypeURL,
		Value:           serializedPubKey,
		KeyMaterialType: tinkpb.KeyData_ASYMMETRIC_PUBLIC,
	}, nil
}

var _ registry.PrivateKeyManager = (*nistPECDHKWPrivateKeyManager)(nil)

func newECDHNISTPAESPrivateKeyManager() *nistPECDHKWPrivateKeyManager {
	return new(nistPECDHKWPrivateKeyManager)
}

func validateKeyFormat(params *ecdhpb.EcdhAeadParams) (elliptic.Curve, error) {
	var (
		c   elliptic.Curve
		err error
	)

	if params.EncParams.CEK == nil {
		c, err = hybrid.GetCurve(params.KwParams.CurveType.String())
		if err != nil {
			return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key: %w", err)
		}
	} else {
		c = elliptic.P384()
	}

	km, err := registry.GetKeyManager(params.EncParams.AeadEnc.TypeUrl)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key: %w", err)
	}

	_, err = km.NewKeyData(params.EncParams.AeadEnc.Value)
	if err != nil {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key: %w", err)
	}

	if params.KwParams.KeyType.String() != ecdhpb.KeyType_EC.String() {
		return nil, fmt.Errorf("nistpkw_ecdh_private_key_manager: invalid key type %v",
			params.KwParams.KeyType)
	}

	return c, nil
}
