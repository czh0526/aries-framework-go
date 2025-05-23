package store

import (
	"fmt"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const (
	RemoteProviderStoreName = "remote_providers"
	RemoteProviderRecordTag = "record"
)

type RemoteProviderRecord struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
}

type RemoteProviderStore interface {
	Get(id string) (*RemoteProviderRecord, error)
	GetAll() ([]RemoteProviderRecord, error)
	Save(endpoint string) (*RemoteProviderRecord, error)
	Delete(id string) error
}

func NewRemoteProviderStore(storeProvider spistorage.Provider) (*RemoteProviderStoreImpl, error) {
	store, err := storeProvider.OpenStore(RemoteProviderStoreName)
	if err != nil {
		return nil, fmt.Errorf("failed to open store: %w", err)
	}

	err = storeProvider.SetStoreConfig(RemoteProviderStoreName,
		spistorage.StoreConfiguration{
			TagNames: []string{RemoteProviderRecordTag},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set store config: %w", err)
	}

	return &RemoteProviderStoreImpl{
		store: store,
	}, nil
}
