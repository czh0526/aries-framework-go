package did

import (
	"encoding/json"
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"log"
)

type ConnectionStore interface {
	GetDID(key string) (string, error)
	SaveDID(did string, keys ...string) error
	SaveDIDFromDoc(doc *didmodel.Doc) error
	SaveDIDByResolving(did string, keys ...string) error
}

type ConnectionStoreImpl struct {
	store spistorage.Store
	vdr   vdrapi.Registry
}

type didRecord struct {
	DID string `json:"did,omitempty"`
}

func (c *ConnectionStoreImpl) SaveDID(did string, keys ...string) error {
	for _, key := range keys {
		err := c.saveDID(did, key)
		if err != nil {
			return fmt.Errorf("saving DID in did map: %w", err)
		}
	}

	return nil
}

func (c *ConnectionStoreImpl) SaveDIDFromDoc(doc *didmodel.Doc) error {
	var keys []string

	svc, err := service.CreateDestination(doc)
	if err == nil {
		keys = append(keys, svc.RecipientKeys...)
	} else {
		log.Printf("saveDIDFromDoc: CreateDestination of DID Document returned error [%v], no keys will be "+
			"linked for this DID `%s` in the connection store", err, doc.ID)
	}
}

func (c *ConnectionStoreImpl) saveDID(did, key string) error {
	data := didRecord{
		DID: did,
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return c.store.Put(key, bytes)
}
