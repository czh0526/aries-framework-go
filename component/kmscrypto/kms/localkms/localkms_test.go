package localkms

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
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
