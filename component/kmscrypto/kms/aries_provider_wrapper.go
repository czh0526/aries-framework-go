package kms

import (
	"errors"
	"fmt"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const AriesWrapperStoreName = "kmsdb"

type ariesProviderKMSStoreWrapper struct {
	store spistorage.Store
}

func (a *ariesProviderKMSStoreWrapper) Get(keysetID string) (key []byte, err error) {
	key, err = a.store.Get(keysetID)
	if err != nil {
		if errors.Is(err, spistorage.ErrDataNotFound) {
			return nil, fmt.Errorf("%w. Underlying error: %s", ErrKeyNotFound, err.Error())
		}
		return nil, err
	}

	return key, err
}

func (a *ariesProviderKMSStoreWrapper) Delete(keysetID string) error {
	return a.store.Delete(keysetID)
}

func (a *ariesProviderKMSStoreWrapper) Put(keysetID string, key []byte) error {
	return a.store.Put(keysetID, key)
}

func NewAriesProviderWrapper(provider spistorage.Provider) (spikms.Store, error) {
	store, err := provider.OpenStore(AriesWrapperStoreName)
	if err != nil {
		return nil, err
	}

	storeWrapper := ariesProviderKMSStoreWrapper{
		store: store,
	}

	return &storeWrapper, nil
}
