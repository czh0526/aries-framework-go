package localkms

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	mocksecretlock "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/secretlock"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/local"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/hkdf"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"io/ioutil"
	"os"
	"testing"
)

const testMasterKeyURI = keywrapper.LocalKeyURIPrefix + "test/key/uri"

type inMemoryKMSStore struct {
	keys map[string][]byte
}

func newInMemoryKMSStore() *inMemoryKMSStore {
	return &inMemoryKMSStore{keys: make(map[string][]byte)}
}

func (i *inMemoryKMSStore) Put(keysetID string, key []byte) error {
	i.keys[keysetID] = key

	return nil
}

func (i *inMemoryKMSStore) Get(keysetID string) (key []byte, err error) {
	key, found := i.keys[keysetID]
	if !found {
		return nil, kms.ErrKeyNotFound
	}

	return key, nil
}

func (i *inMemoryKMSStore) Delete(keysetID string) error {
	delete(i.keys, keysetID)

	return nil
}

type mockStore struct {
	errPut error
	errGet error
}

func (m *mockStore) Put(string, []byte) error {
	return m.errPut
}

func (m *mockStore) Get(string) ([]byte, error) {
	return nil, m.errGet
}

func (m *mockStore) Delete(string) error {
	return nil
}

type mockProvider struct {
	storage    spikms.Store
	secretLock spisecretlock.Service
}

func (m *mockProvider) StorageProvider() spikms.Store {
	return m.storage
}

func (m mockProvider) SecretLock() spisecretlock.Service {
	return m.secretLock
}

func TestNewKMS(t *testing.T) {
	t.Run("test Create() calls with bad key template string", func(t *testing.T) {
		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage: newInMemoryKMSStore(),
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: base64.URLEncoding.EncodeToString([]byte("encrypt-msg")),
				ValDecrypt: base64.URLEncoding.EncodeToString([]byte("decrypt-msg")),
			},
		})
		require.NoError(t, err)
		require.NotEmpty(t, localKms)

		id, kh, err := localKms.Create("")
		require.Error(t, err)
		require.Empty(t, kh)
		require.Empty(t, id)

		id, kh, err = localKms.Create("unsupported")
		require.Error(t, err)
		require.Empty(t, kh)
		require.Empty(t, id)
	})

	t.Run("test Create() with failure to store key", func(t *testing.T) {
		putErr := fmt.Errorf("failed to put data")
		getErr := kms.ErrKeyNotFound
		mockStore := &mockStore{
			errPut: putErr,
			errGet: getErr,
		}

		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage: mockStore,
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: base64.URLEncoding.EncodeToString([]byte("encrypt-msg")),
				ValDecrypt: base64.URLEncoding.EncodeToString([]byte("decrypt-msg")),
			},
		})
		require.NoError(t, err)

		id, kh, err := localKms.Create(spikms.AES128GCMType)
		require.True(t, errors.Is(err, putErr))
		require.Empty(t, kh)
		require.Empty(t, id)
	})

	t.Run("test Create() success to store key but fail to get key from store", func(t *testing.T) {
		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage: newInMemoryKMSStore(),
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: base64.URLEncoding.EncodeToString([]byte("encrypt-msg")),
				ValDecrypt: base64.URLEncoding.EncodeToString([]byte("decrypt-msg")),
			},
		})
		require.NoError(t, err)

		id, kh, err := localKms.Create(spikms.AES128GCMType)
		require.NoError(t, err)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		getErr := errors.New("failed to get data")
		mockStore := &mockStore{
			errGet: getErr,
		}
		localKms2, err := New(testMasterKeyURI, &mockProvider{
			storage: mockStore,
			secretLock: &mocksecretlock.MockSecretLock{
				ValEncrypt: base64.URLEncoding.EncodeToString([]byte("encrypt-msg")),
				ValDecrypt: base64.URLEncoding.EncodeToString([]byte("decrypt-msg")),
			},
		})
		require.NoError(t, err)

		kh, err = localKms2.Get(id)
		require.True(t, errors.Is(err, getErr))
		require.Empty(t, kh)
	})

	t.Run("create valid key byte not available for Export", func(t *testing.T) {
		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage:    newInMemoryKMSStore(),
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		kid, _, err := localKms.Create(spikms.AES128GCMType)
		require.NoError(t, err)

		_, _, err = localKms.ExportPubKeyBytes(kid)
		require.EqualError(t, err, "exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: failed to get public keyset handle: keyset.Handle: keyset contains a non-private key")
	})

	t.Run("create valid key byte and available for Export", func(t *testing.T) {
		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage:    newInMemoryKMSStore(),
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		kid, _, err := localKms.Create(spikms.ECDSAP384TypeIEEEP1363)
		require.NoError(t, err)

		pbBytes, kt, err := localKms.ExportPubKeyBytes(kid)
		require.NoError(t, err)
		require.NotEmpty(t, kt)
		require.NotEmpty(t, pbBytes)
	})

	t.Run("create And Export invalid key", func(t *testing.T) {
		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage:    newInMemoryKMSStore(),
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)

		_, _, err = localKms.CreateAndExportPubKeyBytes("unsupported")
		require.EqualError(t, err, "createAndExportPubKeyBytes: failed to create new key: "+
			"failed to getKeyTemplate: getKeyTemplate: key type `unsupported` unrecognized")

		_, _, err = localKms.CreateAndExportPubKeyBytes(spikms.HMACSHA256Tag256Type)
		require.EqualError(t, err, "createAndExportPubKeyBytes: failed to export new public key bytes: "+
			"exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: "+
			"failed to get public keyset handle: keyset.Handle: keyset contains a non-private key")
	})
}

func TestEncryptRotateDecrypt_Success(t *testing.T) {
	sl := createMasterKeyAndSecretLock(t)

	localKms, err := New(testMasterKeyURI, &mockProvider{
		storage:    newInMemoryKMSStore(),
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, localKms)

	keyTemplates := []spikms.KeyType{
		spikms.AES128GCMType,
		spikms.AES256GCMNoPrefixType,
		spikms.AES256GCMType,
		spikms.ChaCha20Poly1305Type,
		spikms.XChaCha20Poly1305Type,
	}

	for _, v := range keyTemplates {
		keyID, keyHandle, e := localKms.Create(v)
		require.NoError(t, e, "failed on template %v", v)
		require.NotEmpty(t, keyHandle)
		require.NotEmpty(t, keyID)

		c := tinkcrypto.Crypto{}
		msg := []byte("Test Rotation Message")
		aad := []byte("some additional data")

		cipherText, e := c.Encrypt(msg, aad, keyHandle)
		require.NoError(t, e)

		newKeyID, rotatedKeyHandle, e := localKms.Rotate(v, keyID)
		require.NoError(t, e)
		require.NotEmpty(t, rotatedKeyHandle)
		require.NotEqual(t, newKeyID, keyID)

		decryptedMsg, e := c.Decrypt(cipherText, aad, rotatedKeyHandle)
		require.NoError(t, e)
		require.Equal(t, msg, decryptedMsg)
	}
}

func TestLocalKMS_Success(t *testing.T) {
	sl := createMasterKeyAndSecretLock(t)

	keys := make(map[string][]byte)
	testStore := newInMemoryKMSStore()

	testStore.keys = keys

	localKms, err := New(testMasterKeyURI, &mockProvider{
		storage:    testStore,
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, localKms)

	keyTypes := []spikms.KeyType{
		spikms.AES128GCMType,
		spikms.AES256GCMNoPrefixType,
		spikms.AES256GCMType,
		spikms.ChaCha20Poly1305Type,
		spikms.XChaCha20Poly1305Type,
		spikms.ECDSAP256TypeDER,
		spikms.ECDSAP384TypeDER,
		spikms.ECDSAP521TypeDER,
		spikms.ECDSAP256TypeIEEEP1363,
		spikms.ECDSAP384TypeIEEEP1363,
		spikms.ECDSAP521TypeIEEEP1363,
		spikms.ECDSAP384TypeIEEEP1363,
		spikms.ED25519Type,
		spikms.NISTP256ECDHKWType,
		spikms.NISTP384ECDHKWType,
		spikms.NISTP521ECDHKWType,
		spikms.X25519ECDHKWType,
		//spikms.BLS12381G2Type,
		spikms.ECDSASecp256k1TypeDER,
		spikms.ECDSASecp256k1TypeIEEEP1363,
	}

	for _, kt := range keyTypes {
		if kt == spikms.ECDSASecp256k1TypeDER {
			_, _, e := localKms.Create(kt)
			require.EqualError(t, e, "create: Unable to create kms key: Secp256K1 is not supported by DER format")
			continue
		}

		// 创建一个 KeySet， 返回 keyId + Handle
		keyID, newKeyHandle, e := localKms.Create(kt)
		require.NoError(t, e)
		require.NotEmpty(t, newKeyHandle)
		require.NotEmpty(t, keyID)

		ks, ok := keys[keyID]
		require.True(t, ok)
		require.NotEmpty(t, ks)

		newKeySetInfo := newKeyHandle.(*keyset.Handle).KeysetInfo()

		loadedKeyHandle, e := localKms.Get(keyID)
		require.NoError(t, e)
		require.NotEmpty(t, loadedKeyHandle)

		loadedKeySetInfo := loadedKeyHandle.(*keyset.Handle).KeysetInfo()
		require.Equal(t, len(newKeySetInfo.KeyInfo), len(loadedKeySetInfo.KeyInfo))
	}
}

// 测试通过 KeyType 获取 KeyTemplate
func TestLocalKMS_getKeyTemplate(t *testing.T) {
	keyTemplate, err := getKeyTemplate(spikms.HMACSHA256Tag256Type)
	require.NoError(t, err)
	require.NotEmpty(t, keyTemplate)
	require.Equal(t, "type.googleapis.com/google.crypto.tink.HmacKey", keyTemplate.TypeUrl)
}

func TestLocalKMS_GetKey(t *testing.T) {
	t.Run("test Create() success And GetKey", func(t *testing.T) {
		localKms, err := New(testMasterKeyURI, &mockProvider{
			storage:    newInMemoryKMSStore(),
			secretLock: &noop.NoLock{},
		})
		require.NoError(t, err)
		require.NotEmpty(t, localKms)

		id, kh, err := localKms.Create(spikms.AES128GCMType)
		require.NoError(t, err)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		kh, err = localKms.Get(id)
		require.NoError(t, err)
		require.NotNil(t, kh)
	})
}

func createMasterKeyAndSecretLock(t *testing.T) spisecretlock.Service {
	t.Helper()

	// 生成文件
	masterKeyFilePath := "masterKey_file.txt"
	tmpfile, err := ioutil.TempFile("", masterKeyFilePath)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, tmpfile.Close())
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()

	// 随机数
	masterKeyContent := random.GetRandomBytes(uint32(32))
	require.NotEmpty(t, masterKeyContent)

	// 生成 salt
	passphrase := "secretPassphrase"
	keySize := sha256.Size
	salt := make([]byte, keySize)
	_, err = rand.Read(salt)
	require.NoError(t, err)

	// 创建一个 MasterLock
	masterLocker, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
	require.NoError(t, err)
	require.NotEmpty(t, masterLocker)

	// 数据加密
	masterLockEnc, err := masterLocker.Encrypt("", &spisecretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})
	require.NoError(t, err)
	require.NotEmpty(t, masterLockEnc)

	// 将`加密数据`写入文件
	n, err := tmpfile.Write([]byte(masterLockEnc.Ciphertext))
	require.NoError(t, err)
	require.Equal(t, len(masterLockEnc.Ciphertext), n)

	// 读取`加密数据`
	r, err := local.MasterKeyFromPath(tmpfile.Name())
	require.NoError(t, err)
	require.NotEmpty(t, r)

	// 构建一个 secretLock
	s, err := local.NewService(r, masterLocker)
	require.NoError(t, err)
	require.NotEmpty(t, s)

	return s
}
