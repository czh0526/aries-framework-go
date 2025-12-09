package mock

import (
	"bytes"
	"encoding/json"
	"fmt"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
	mockstorage "github.com/czh0526/aries-framework-go/component/storageutil/mock/storage"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
)

type ContextStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrPut    error
	ErrImport error
	ErrDelete error
}

func (c *ContextStore) Get(u string) (*jsonld.RemoteDocument, error) {
	if c.ErrGet != nil {
		return nil, c.ErrGet
	}

	b, err := c.Store.Get(u)
	if err != nil {
		return nil, fmt.Errorf("get context from store: %w", err)
	}

	var rd jsonld.RemoteDocument
	if err := json.Unmarshal(b, &rd); err != nil {
		return nil, fmt.Errorf("unmarshal context document: %w", err)
	}

	return &rd, nil
}

func (c *ContextStore) Put(u string, rd *jsonld.RemoteDocument) error {
	if c.ErrPut != nil {
		return c.ErrPut
	}

	b, err := json.Marshal(rd)
	if err != nil {
		return fmt.Errorf("marshal remote document: %w", err)
	}

	if err := c.Store.Put(u, b); err != nil {
		return fmt.Errorf("put remote document: %w", err)
	}

	return nil
}

func (c *ContextStore) Import(documents []ldcontext.Document) error {
	if c.ErrImport != nil {
		return c.ErrImport
	}

	for _, d := range documents {
		document, err := jsonld.DocumentFromReader(bytes.NewReader(d.Content))
		if err != nil {
			return fmt.Errorf("document from reader: %w", err)
		}

		rd := jsonld.RemoteDocument{
			DocumentURL: d.DocumentURL,
			Document:    document,
		}
		b, err := json.Marshal(rd)
		if err != nil {
			return fmt.Errorf("marshal remote document: %w", err)
		}

		if err = c.Store.Put(d.URL, b, spistorage.Tag{
			Name: ldstore.ContextRecordTag,
		}); err != nil {
			return fmt.Errorf("put context document: %w", err)
		}
	}

	return nil
}

func (c *ContextStore) Delete(documents []ldcontext.Document) error {
	if c.ErrDelete != nil {
		return c.ErrDelete
	}

	for _, d := range documents {
		if err := c.Store.Delete(d.URL); err != nil {
			return fmt.Errorf("delete context document: %w", err)
		}
	}
	return nil
}

var _ ldstore.ContextStore = (*ContextStore)(nil)

func NewMockContextStore() *ContextStore {
	return &ContextStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}
