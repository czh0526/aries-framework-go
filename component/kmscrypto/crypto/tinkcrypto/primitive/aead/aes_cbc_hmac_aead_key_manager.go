package aead

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	cbcpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_go_proto"
	aeadpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
	subtleaead "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	subtlemac "github.com/tink-crypto/tink-go/v2/mac/subtle"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	hmacpb "github.com/tink-crypto/tink-go/v2/proto/hmac_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"google.golang.org/protobuf/proto"
)

const (
	aesCBCHMACAEADKeyVersion = 0
	aesCBCHMACAEADTypeURL    = "type.hyperledger.org/hyperledger.aries.crypto.tink.AesCbcHmacAeadKey"
	minHMACKeySizeInBytes    = 16
	minTagSizeInBytes        = 10

	maxTagSizeSHA1   = 20
	maxTagSizeSHA224 = 28
	maxTagSizeSHA256 = 32
	maxTagSizeSHA384 = 48
	maxTagSizeSHA512 = 64
)

var (
	errInvalidAESCBCHMACAEADKey       = fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid key")
	errInvalidAESCBCHMACAEADKeyFormat = fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid key format")
	maxTagSize                        = map[commonpb.HashType]uint32{
		commonpb.HashType_SHA1:   maxTagSizeSHA1,
		commonpb.HashType_SHA224: maxTagSizeSHA224,
		commonpb.HashType_SHA256: maxTagSizeSHA256,
		commonpb.HashType_SHA384: maxTagSizeSHA384,
		commonpb.HashType_SHA512: maxTagSizeSHA512,
	}
)

func newAESCBCHMACAEADKeyManager() *aesCBCHMACAEADKeyManager {
	return &aesCBCHMACAEADKeyManager{}
}

type aesCBCHMACAEADKeyManager struct{}

// Primitive creates an AEAD fpr tje given serialized AESCBCHMACAEADKey proto.
func (km *aesCBCHMACAEADKeyManager) Primitive(serializedKey []byte) (any, error) {
	if len(serializedKey) == 0 {
		return nil, errInvalidAESCBCHMACAEADKey
	}

	key := new(aeadpb.AesCbcHmacAeadKey)
	if err := proto.Unmarshal(serializedKey, key); err != nil {
		return nil, errInvalidAESCBCHMACAEADKey
	}

	if err := km.validateKey(key); err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid key: %s", err)
	}

	cbc, err := subtle.NewAESCBC(key.AesCbcKey.KeyValue)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac_aead_key_manager: cannot create aes_cbc primitive: %s", err)
	}

	hmacKey := key.HmacKey
	hmac, err := subtlemac.NewHMAC(hmacKey.Params.Hash.String(), hmacKey.KeyValue, hmacKey.Params.TagSize)
	if err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac_aead_key_manager: cannot create hmac primitive: %s", err)
	}

	aead, err := subtleaead.NewEncryptThenAuthenticate(cbc, hmac, int(hmacKey.Params.TagSize))
	if err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac_aead_key_manager: cannot create encrypt then authenticate primitive: %s", err)
	}

	return aead, nil
}

func (km *aesCBCHMACAEADKeyManager) DoesSupport(typeURL string) bool {
	return typeURL == aesCBCHMACAEADTypeURL
}

func (km *aesCBCHMACAEADKeyManager) TypeURL() string {
	return aesCBCHMACAEADTypeURL
}

func (km *aesCBCHMACAEADKeyManager) NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error) {
	key, err := km.NewKey(serializedKeyFormat)
	if err != nil {
		return nil, err
	}

	serializedKey, err := proto.Marshal(key)
	if err != nil {
		return nil, err
	}

	return &tinkpb.KeyData{
		TypeUrl:         km.TypeURL(),
		Value:           serializedKey,
		KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
	}, nil
}

func (km *aesCBCHMACAEADKeyManager) NewKey(serializedKeyFormat []byte) (proto.Message, error) {
	if len(serializedKeyFormat) == 0 {
		return nil, errInvalidAESCBCHMACAEADKeyFormat
	}

	keyFormat := new(aeadpb.AesCbcHmacAeadKeyFormat)
	if err := proto.Unmarshal(serializedKeyFormat, keyFormat); err != nil {
		return nil, errInvalidAESCBCHMACAEADKeyFormat
	}

	if err := km.validateKeyFormat(keyFormat); err != nil {
		return nil, fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid key format: %w", err)
	}

	return &aeadpb.AesCbcHmacAeadKey{
		Version: aesCBCHMACAEADKeyVersion,
		AesCbcKey: &cbcpb.AesCbcKey{
			Version:  aesCBCHMACAEADKeyVersion,
			KeyValue: random.GetRandomBytes(keyFormat.AesCbcKeyFormat.KeySize),
		},
		HmacKey: &hmacpb.HmacKey{
			Version:  aesCBCHMACAEADKeyVersion,
			KeyValue: random.GetRandomBytes(keyFormat.HmacKeyFormat.KeySize),
			Params:   keyFormat.HmacKeyFormat.Params,
		},
	}, nil
}

func (km *aesCBCHMACAEADKeyManager) validateKeyFormat(format *aeadpb.AesCbcHmacAeadKeyFormat) error {
	// Validate AesCtrKeyFormat.
	if err := subtle.ValidateAESKeySize(format.AesCbcKeyFormat.KeySize); err != nil {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: %w", err)
	}

	// Validate HmacKeyFormat.
	hmacKeyFormat := format.HmacKeyFormat
	if hmacKeyFormat.KeySize < minHMACKeySizeInBytes {
		return errors.New("aes_cbc_hmac_aead_key_manager: HMAC KeySize is too small")
	}

	if hmacKeyFormat.Params.TagSize < minTagSizeInBytes {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid HmacParams: TagSize %d is too small",
			hmacKeyFormat.Params.TagSize)
	}

	tagSize, ok := maxTagSize[hmacKeyFormat.Params.Hash]
	if !ok {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid HmacParams: HashType %q not supported",
			hmacKeyFormat.Params.Hash)
	}

	if hmacKeyFormat.Params.TagSize > tagSize {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: invalid HmacParams: TagSize %d is too big for HashType %q",
			hmacKeyFormat.Params.TagSize, hmacKeyFormat.Params.Hash)
	}

	return nil
}

func (km *aesCBCHMACAEADKeyManager) validateKey(key *aeadpb.AesCbcHmacAeadKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, aesCBCHMACAEADKeyVersion); err != nil {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: %w", err)
	}

	if err := keyset.ValidateKeyVersion(key.AesCbcKey.Version, aesCBCHMACAEADKeyVersion); err != nil {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: %w", err)
	}

	if err := keyset.ValidateKeyVersion(key.HmacKey.Version, aesCBCHMACAEADKeyVersion); err != nil {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: %w", err)
	}

	// Validate AesCtrKey.
	keySize := uint32(len(key.AesCbcKey.KeyValue))
	if err := subtle.ValidateAESKeySize(keySize); err != nil {
		return fmt.Errorf("aes_cbc_hmac_aead_key_manager: %w", err)
	}

	return nil
}
