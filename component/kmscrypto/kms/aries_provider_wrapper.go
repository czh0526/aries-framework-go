package kms

import (
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const AriesWrapperStoreName = "kmsdb"

type ariesProviderKMSStoreWrapper struct {
	store spistorage.Store
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
