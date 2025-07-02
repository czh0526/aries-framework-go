package localkms

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	mocksecretlock "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/secretlock"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/local/masterlock/hkdf"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
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

	kmsService, err := New(testMasterKeyURI, &mockProvider{
		storage:    newInMemoryKMSStore(),
		secretLock: sl,
	})
	require.NoError(t, err)
	require.NotEmpty(t, kmsService)
}

func createMasterKeyAndSecretLock(t *testing.T) *mockProvider {
	t.Helper()

	masterKeyFilePath := "masterKey_file.txt"
	tmpfile, err := ioutil.TempFile("", masterKeyFilePath)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, tmpfile.Close())
		require.NoError(t, os.Remove(tmpfile.Name()))
	}()

	masterKeyContent := random.GetRandomBytes(uint32(32))
	require.NotEmpty(t, masterKeyContent)

	passphrase := "secretPassphrase"
	keySize := sha256.Size
	salt := make([]byte, keySize)
	_, err = rand.Read(salt)
	require.NotEmpty(t, err)

	masterLocker, err := hkdf.NewMasterLock(passphrase, sha256.New, salt)
	require.NoError(t, err)
	require.NotEmpty(t, masterLocker)

	masterLockEnc, err := masterLocker.Encrypt("", &spisecretlock.EncryptRequest{
		Plaintext: string(masterKeyContent),
	})
	require.NoError(t, err)
	require.NotEmpty(t, masterLockEnc)

	n, err := tmpfile.Write([]byte(masterLockEnc.Ciphertext))
	require.NoError(t, err)
	require.Equal(t, len(masterLockEnc.Ciphertext), n)
}
