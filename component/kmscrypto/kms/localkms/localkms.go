package localkms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/tink-crypto/tink-go/v2/aead"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
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
	return l.getKeySet(keyID)
}

func (l *LocalKMS) ExportPubKeyBytes(id string) ([]byte, spikms.KeyType, error) {
	// 根据 id 获取 Keyset Handle
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
	switch pk := privKey.(type) {
	case *ecdsa.PrivateKey:
		return l.importECDSAKey(pk, kt, opts...)
	case ed25519.PrivateKey:
		return l.importEd25519Key(pk, kt, opts...)
	case *bbs12381g2pub.PrivateKey:
		return "", nil, fmt.Errorf("import private key does not support BBS+ private key")
	default:
		return "", nil, fmt.Errorf("import private key does not support this key type or key is public")
	}
}

func (l *LocalKMS) importECDSKey(privKey *ecdsa.PrivateKey, kt spikms.KeyType, opts ...spikms.KeyOpts) (string, *keyset.Handle, error) {

}

func (l *LocalKMS) importKeySet(ks *tinkpb.Keyset, opts ...spikms.PrivateKeyOpts) (string, *keyset.Handle, error) {
	ksID, err := l.writeImportedKey(ks, opts...)

}

func (l *LocalKMS) writeImportedKey(ks *tinkpb.Keyset, opts ...spikms.PrivateKeyOpts) (string, error) {
	serializedKeyset, err := proto.Marshal(ks)
	if err != nil {
		return "", fmt.Errorf("invalid keyset data")
	}

	encrypted, err := l.primaryKeyEnvAEAD.Encrypt(serializedKeyset, []byte{})
	if err != nil {
		return "", fmt.Errorf("encrypted failed: %w", err)
	}

	ksInfo, err := getKeysetInfo(ks)
	if err != nil {
		return "", fmt.Errorf("cannot get keyset info: %w", err)
	}

	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,

		KeysetInfo: ksInfo,
	}

	buf := new(bytes.Buffer)
	jsonKeysetWriter := keyset.NewJSONWriter(buf)

	err = jsonKeysetWriter.WriteEncrypted(encryptedKeyset)
	if err != nil {
		return "", fmt.Errorf("failed to write keyset as json: %w", err)
	}

	return writeToStore(l.store, buf, opts...)
}

func (l *LocalKMS) getKeySet(id string) (*keyset.Handle, error) {
	localDBReader := newReader(l.store, id)

	jsonKeysetReader := keyset.NewJSONReader(localDBReader)

	kh, err := keyset.Read(jsonKeysetReader, l.primaryKeyEnvAEAD)
	if err != nil {
		return nil, fmt.Errorf("getKeySet: failed to read json keyset from reader: %v", err)
	}

	return kh, nil
}

// generateKID 导出公钥，根据公钥构建 kid
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
	if err != nil {
		return nil, "", fmt.Errorf("exportPubKeyBytes: failed to create keyset with no secrets (public key masterial): %w", err)
	}

	return buf.Bytes(), pubKeyWriter.KeyType, nil
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

// setKIDForCompositeKey 将 kid 写入到 marshalledKey 中
func setKIDForCompositeKey(marshalledKey []byte, kid string) ([]byte, error) {
	pubKey := &spicrypto.PublicKey{}

	err := json.Unmarshal(marshalledKey, pubKey)
	if err != nil {
		return marshalledKey, nil
	}

	pubKey.KID = kid
	return json.Marshal(pubKey)
}

// New returns a new instance of a local KMS.
func New(primaryKeyURI string, p spikms.Provider) (*LocalKMS, error) {
	secretLock := p.SecretLock()

	kw, err := keywrapper.New(secretLock, primaryKeyURI)
	if err != nil {
		return nil, fmt.Errorf("new: failed to create new keywrapper: %v", err)
	}

	keyEnvelopeAEAD := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kw)

	return &LocalKMS{
		store:             p.StorageProvider(),
		secretLock:        secretLock,
		primaryKeyURI:     primaryKeyURI,
		primaryKeyEnvAEAD: keyEnvelopeAEAD,
	}, nil
}
