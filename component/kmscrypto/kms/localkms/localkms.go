package localkms

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"log"
)

const (
	Namespace = kms.AriesWrapperStoreName

	ecdsaPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

type LocalKMS struct {
}

func (l *LocalKMS) Create(kt spikms.KeyType, opts ...spikms.KeyOpts) (string, interface{}, error) {
	if kt == "" {
		return "", nil, fmt.Errorf("failed to creat new key, missing key type")
	}

	if kt == spikms.ECDSASecp256k1DER {
		return "", nil, fmt.Errorf("create: Unable to create kms key: Secp256K1 is not supported by DER format")
	}

	keyTemplate, err := getKeyTemplate(kt, opts...)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to getKeyTemplate: %v", err)
	}

	return keyID, kh, nil
}

func (l LocalKMS) Get(keyID string) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (l LocalKMS) ExportPubKeyBytes(keyID string) ([]byte, spikms.KeyType, error) {
	//TODO implement me
	panic("implement me")
}

func (l LocalKMS) CreateAndExportPubKeyBytes(kt spikms.KeyType, opts ...spikms.KeyOpts) (string, []byte, error) {
	//TODO implement me
	panic("implement me")
}

func (l LocalKMS) PubKeyBytesToHandle(pubKey []byte, kt spikms.KeyType, opts ...spikms.KeyOpts) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (l LocalKMS) ImportPrivateKey(privKey interface{}, kt spikms.KeyType, opts ...spikms.PrivateKeyOpts) (string, interface{}, error) {
	//TODO implement me
	panic("implement me")
}

// New returns a new instance of a local KMS.
func New(primaryKeyURI string, p spikms.Provider) (*LocalKMS, error) {
	log.Printf("【default】New LocalKMS")
	return &LocalKMS{}, nil
}
