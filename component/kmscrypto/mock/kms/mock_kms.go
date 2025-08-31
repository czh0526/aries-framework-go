package kms

import (
	comp_kms "github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type KeyManager struct {
	// Create XXX
	CreateKeyID    string
	CreateKeyValue *keyset.Handle
	CreateKeyErr   error
	CreateKeyFn    func(kt spikms.KeyType) (string, interface{}, error)
	// Get XXX
	GetKeyValue *keyset.Handle
	GetKeyErr   error
	// Rotate
	RotateKeyID    string
	RotateKeyValue *keyset.Handle
	RotateKeyErr   error
	// Export XXX
	ExportPubKeyBytesErr   error
	ExportPubKeyBytesValue []byte
	ExportPubKeyTypeValue  spikms.KeyType
	// Create And Export
	CrAndExportPubKeyValue []byte
	CrAndExportPubKeyID    string
	CrAndExportPubKeyErr   error
	// PubKey
	PubKeyBytesToHandleErr   error
	PubKeyBytesToHandleValue *keyset.Handle
	// Import XXX
	ImportPrivateKeyErr   error
	ImportPrivateKeyID    string
	ImportPrivateKeyValue *keyset.Handle
}

func (k *KeyManager) Create(kt spikms.KeyType, opts ...spikms.KeyOpts) (string, interface{}, error) {
	if k.CreateKeyErr != nil {
		return "", nil, k.CreateKeyErr
	}
	if k.CreateKeyFn != nil {
		return k.CreateKeyFn(kt)
	}

	return k.CreateKeyID, k.CreateKeyValue, nil
}

func (k *KeyManager) Get(keyID string) (interface{}, error) {
	if k.GetKeyErr != nil {
		return nil, k.GetKeyErr
	}

	return k.GetKeyValue, nil
}

func (k *KeyManager) Rotate(kt spikms.KeyType, keyID string, opts ...spikms.KeyOpts) (string, interface{}, error) {
	if k.RotateKeyErr != nil {
		return "", nil, k.RotateKeyErr
	}

	return k.RotateKeyID, k.RotateKeyValue, nil
}

func (k *KeyManager) ExportPubKeyBytes(keyID string) ([]byte, spikms.KeyType, error) {
	if k.ExportPubKeyBytesErr != nil {
		return nil, "", k.ExportPubKeyBytesErr
	}

	return k.ExportPubKeyBytesValue, k.ExportPubKeyTypeValue, nil
}

func (k *KeyManager) CreateAndExportPubKeyBytes(kt spikms.KeyType, opts ...spikms.KeyOpts) (string, []byte, error) {
	if k.CrAndExportPubKeyErr != nil {
		return "", nil, k.CrAndExportPubKeyErr
	}
	return k.CrAndExportPubKeyID, k.CrAndExportPubKeyValue, nil
}

func (k *KeyManager) PubKeyBytesToHandle(pubKey []byte, keyType spikms.KeyType,
	opts ...spikms.KeyOpts) (interface{}, error) {
	if k.PubKeyBytesToHandleErr != nil {
		return nil, k.PubKeyBytesToHandleErr
	}
	return k.PubKeyBytesToHandleValue, nil
}

func (k *KeyManager) ImportPrivateKey(privKey interface{}, kt spikms.KeyType, opts ...spikms.PrivateKeyOpts) (
	string, interface{}, error) {
	if k.ImportPrivateKeyErr != nil {
		return "", nil, k.ImportPrivateKeyErr
	}

	return k.ImportPrivateKeyID, k.ImportPrivateKeyValue, nil
}

type Provider struct {
	storeProvider spikms.Store
	secretLock    spisecretlock.Service
}

func (p *Provider) StorageProvider() spikms.Store {
	return p.storeProvider
}

func (p *Provider) SecretLock() spisecretlock.Service {
	return p.secretLock
}

func NewProviderForKMS(storeProvider spistorage.Provider, secretLock spisecretlock.Service) (*Provider, error) {
	// 构建一个 kms store
	kmsStore, err := comp_kms.NewAriesProviderWrapper(storeProvider)
	if err != nil {
		return nil, err
	}

	return &Provider{
		storeProvider: kmsStore,
		secretLock:    secretLock,
	}, nil
}
