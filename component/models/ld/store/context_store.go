package store

import (
	"fmt"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
)

const (
	ContextStoreName = "ldcontexts"
	ContextRecordTag = "record"
)

type ContextStore interface {
	Get(u string) (jsonld.RemoteDocument, error)
	Put(u string, rd *jsonld.RemoteDocument) error
	Import(documents []ldcontext.Document) error
	Delete(documents []ldcontext.Document) error
}

func NewContextStore(storeProvider spistorage.Provider) (*ContextStoreImpl, error) {
	store, err := storeProvider.OpenStore(ContextStoreName)
	if err != nil {
		return nil, fmt.Errorf("open `context` store failed, err = %w", err)
	}

	err = storeProvider.SetStoreConfig(ContextStoreName,
		spistorage.StoreConfiguration{
			TagNames: []string{ContextRecordTag},
		})
	if err != nil {
		return nil, fmt.Errorf("set store config failed, err = %w", err)
	}

	return &ContextStoreImpl{
		store: store,
	}, nil
}
