package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
	"log"
)

type ContextStoreImpl struct {
	store spistorage.Store
}

func (c *ContextStoreImpl) Get(u string) (*jsonld.RemoteDocument, error) {
	b, err := c.store.Get(u)
	if err != nil {
		return nil, fmt.Errorf("get context from store: %w", err)
	}

	var rd jsonld.RemoteDocument
	if err := json.Unmarshal(b, &rd); err != nil {
		return nil, fmt.Errorf("unmarshal context document: %w", err)
	}

	return &rd, nil
}

func (c *ContextStoreImpl) Put(u string, rd *jsonld.RemoteDocument) error {
	b, err := json.Marshal(rd)
	if err != nil {
		return fmt.Errorf("marshal remote document: %w", err)
	}

	if err := c.store.Put(u, b); err != nil {
		return fmt.Errorf("put remote document: %w", err)
	}

	return nil
}

func (c *ContextStoreImpl) Import(documents []ldcontext.Document) error {
	hashes, err := computeContextHashes(c.store)
	if err != nil {
		return err
	}

	var contexts []ldcontext.Document
	for _, doc := range documents {
		b, err := getRemoteDocumentBytes(doc)
		if err != nil {
			return fmt.Errorf("get remote document bytes failed, err = %w", err)
		}

		// storage 中有的，并且hash一样的，不用重复存储
		if computeHash(b) == hashes[doc.URL] {
			continue
		}

		contexts = append(contexts, doc)
	}

	if err = save(c.store, contexts); err != nil {
		return fmt.Errorf("save context documents failed, err = %w", err)
	}

	return nil
}

func (c *ContextStoreImpl) Delete(documents []ldcontext.Document) error {
	//TODO implement me
	panic("implement me")
}

func computeContextHashes(store spistorage.Store) (map[string]string, error) {
	iter, err := store.Query(ContextRecordTag)
	if err != nil {
		return nil, fmt.Errorf("query store: %w", err)
	}
	defer func() {
		err = iter.Close()
		if err != nil {
			log.Printf("failed to close the iter: %w", err)
		}
	}()

	contexts := make(map[string]string)
	for {
		if ok, err := iter.Next(); !ok || err != nil {
			if err != nil {
				return nil, fmt.Errorf("next entry: %s", err)
			}
			break
		}

		k, err := iter.Key()
		if err != nil {
			return nil, fmt.Errorf("get key: %s", err)
		}
		v, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("get value: %s", err)
		}

		contexts[k] = computeHash(v)
	}

	return contexts, nil
}

func computeHash(v []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(v))
}

func getRemoteDocumentBytes(doc ldcontext.Document) ([]byte, error) {
	document, err := jsonld.DocumentFromReader(bytes.NewReader(doc.Content))
	if err != nil {
		return nil, fmt.Errorf("document from reader: %w", err)
	}

	rdoc := jsonld.RemoteDocument{
		DocumentURL: doc.DocumentURL,
		Document:    document,
	}

	b, err := json.Marshal(rdoc)
	if err != nil {
		return nil, fmt.Errorf("marshal remote document: %w", err)
	}

	return b, nil
}

func save(store spistorage.Store, contexts []ldcontext.Document) error {
	for _, c := range contexts {
		b, err := getRemoteDocumentBytes(c)
		if err != nil {
			return fmt.Errorf("get remote document bytes: %w", err)
		}

		err = store.Put(c.URL, b, spistorage.Tag{Name: ContextRecordTag})
		if err != nil {
			return fmt.Errorf("put context: %w", err)
		}
	}

	return nil
}
