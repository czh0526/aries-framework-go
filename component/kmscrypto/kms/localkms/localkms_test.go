package localkms

import (
	"encoding/base64"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	mocksecretlock "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/secretlock"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
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
	t.Run("test Create() and Rotate() calls with bad key template string", func(t *testing.T) {
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

		id, kh, err = localKms.Create(spikms.AES128GCMType)
		require.NoError(t, err)
		require.NotEmpty(t, kh)
		require.NotEmpty(t, id)

		newID, kh, err := localKms.Rotate("", id)

	})
}
