package mock

import (
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
	mockstorage "github.com/czh0526/aries-framework-go/component/storageutil/mock/storage"
	jsonld "github.com/piprate/json-gold/ld"
)

type ContextStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrPut    error
	ErrImport error
	ErrDelete error
}

func (c *ContextStore) Get(u string) (jsonld.RemoteDocument, error) {
	//TODO implement me
	panic("implement me")
}

func (c *ContextStore) Put(u string, rd *jsonld.RemoteDocument) error {
	//TODO implement me
	panic("implement me")
}

func (c *ContextStore) Import(documents []ldcontext.Document) error {
	//TODO implement me
	panic("implement me")
}

func (c *ContextStore) Delete(documents []ldcontext.Document) error {
	//TODO implement me
	panic("implement me")
}

var _ ldstore.ContextStore = (*ContextStore)(nil)

func NewMockContextStore() *ContextStore {
	return &ContextStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}
