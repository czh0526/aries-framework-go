package did

import (
	"fmt"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const (
	NameSpace  = "didstore"
	didNameKey = "didname"
)

type Store struct {
	store spistorage.Store
}

type provider interface {
	StorageProvider() spistorage.Provider
}

func New(ctx provider) (*Store, error) {
	store, err := ctx.StorageProvider().OpenStore(NameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open did store: %w", err)
	}

	err = ctx.StorageProvider().SetStoreConfig(NameSpace, spistorage.StoreConfiguration{
		TagNames: []string{didNameKey},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	return &Store{store: store}, nil
}
