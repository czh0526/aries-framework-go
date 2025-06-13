package localkms

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"log"
)

const (
	Namespace = kms.AriesWrapperStoreName

	ecdsaPrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

type LocalKMS struct {
	secretLock        spisecretlock.Service
	primaryKeyURI     string
	store             spikms.Store
	primaryKeyEnvAEAD *tinkaead.KMSEnvelopeAEAD
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

	kh, err := keyset.NewHandle(keyTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to create new keyset handle: %v", err)
	}

	keyID, err := l.storeKeySet(kh, kt)
	if err != nil {
		return "", nil, fmt.Errorf("create: failed to store keyset: %v", err)
	}

	return keyID, kh, nil
}

func (l *LocalKMS) Get(keyID string) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (l *LocalKMS) ExportPubKeyBytes(id string) ([]byte, spikms.KeyType, error) {
	kh, err := l.getKeySet(id)
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to get keyset handle: %v", err)
	}

	marshalledKey, kt, err := l.exportPubKeyBytes(kh)
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to export marshalled key: %v", err)
	}

	if kt == spikms.CLCredDefType {
		return marshalledKey, kt, nil
	}

	mUpdatedKey, err := setKIDForCompositeKey(marshalledKey, id)
	return mUpdatedKey, kt, nil
}

func (l *LocalKMS) CreateAndExportPubKeyBytes(kt spikms.KeyType, opts ...spikms.KeyOpts) (string, []byte, error) {
	//TODO implement me
	panic("implement me")
}

func (l *LocalKMS) PubKeyBytesToHandle(pubKey []byte, kt spikms.KeyType, opts ...spikms.KeyOpts) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (l *LocalKMS) ImportPrivateKey(privKey interface{}, kt spikms.KeyType, opts ...spikms.PrivateKeyOpts) (string, interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (l *LocalKMS) generateKID(kh *keyset.Handle, kt spikms.KeyType) (string, error) {
	keyBytes, _, err := l.exportPubKeyBytes(kh)
	if err != nil {
		return "", fmt.Errorf("generateKID: failed to export public key: %v", err)
	}

	return jwkkid.CreateKID(keyBytes, kt)
}

func (l *LocalKMS) exportPubKeyBytes(kh *keyset.Handle) ([]byte, spikms.KeyType, error) {
	pubKH, err := kh.Public()
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to get public keyset handle: %v", err)
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
}

var errInvalidKeyType = errors.New("key type is not supported")

func (l *LocalKMS) storeKeySet(kh *keyset.Handle, kt spikms.KeyType) (string, error) {
	var (
		kid string
		err error
	)

	switch kt {
	case spikms.AES128GCMType, spikms.AES256GCMType, spikms.AES256GCMNoPrefixType, spikms.ChaCha20Poly1305Type,
		spikms.XChaCha20Poly1305Type, spikms.HMACSHA256Tag256Type, spikms.CLMasterSecretType:
		// symmetric keys will have random kid value (generated in the local storeWriter)
	case spikms.CLCredDefType:
		// ignoring custom KID generation for the asymmetric CL CredDef
	default:
		kid, err = l.generateKID(kh, kt)
		if err != nil && !errors.Is(err, errInvalidKeyType) {
			return "", fmt.Errorf("storeKeySet: failed to generate kid: %v", err)
		}
	}

	buf := new(bytes.Buffer)
	jsonKeysetWriter := keyset.NewJSONWriter(buf)

	err = kh.Write(jsonKeysetWriter, l.primaryKeyEnvAEAD)
	if err != nil {
		return "", fmt.Errorf("storeKeySet: failed to write json key to buffer: %v", err)
	}

	if kid != "" {
		return writeToStore(l.store, buf, spikms.WithKeyID(kid))
	}

	return writeToStore(l.store, buf)
}

func writeToStore(store spikms.Store, buf *bytes.Buffer, opts ...spikms.PrivateKeyOpts) (string, error) {
	w := newWriter(store, opts...)

	_, err := w.Write(buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("writeToStore: failed to write buffer to store: %v", err)
	}

	return w.KeysetID, nil
}

// New returns a new instance of a local KMS.
func New(primaryKeyURI string, p spikms.Provider) (*LocalKMS, error) {
	log.Printf("【default】New LocalKMS")
	return &LocalKMS{}, nil
}
