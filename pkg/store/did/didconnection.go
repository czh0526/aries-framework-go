package did

import (
	"encoding/json"
	"errors"
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"log"
)

const StoreName = "didconnection"

var ErrNotFound = errors.New("did not found under given key")

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

func (c *ConnectionStoreImpl) GetDID(key string) (string, error) {
	bytes, err := c.store.Get(key)
	if errors.Is(err, spistorage.ErrDataNotFound) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}

	var record didRecord

	err = json.Unmarshal(bytes, &record)
	if err != nil {
		return "", err
	}

	return record.DID, nil
}

func (c *ConnectionStoreImpl) SaveDIDByResolving(did string, keys ...string) error {
	docResolution, err := c.vdr.Resolve(did)
	if errors.Is(err, vdrapi.ErrNotFound) {
		return c.SaveDID(did, keys...)
	} else if err != nil {
		return fmt.Errorf("failed to read from vdr store: %w", err)
	}

	return c.SaveDIDFromDoc(docResolution.DIDDocument)
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

	return c.SaveDID(doc.ID, keys...)
}

var _ ConnectionStore = (*ConnectionStoreImpl)(nil)

type didRecord struct {
	DID string `json:"did,omitempty"`
}

type connectionProvider interface {
	StorageProvider() spistorage.Provider
	VDRegistry() vdrapi.Registry
}

func NewConnectionStore(ctx connectionProvider) (*ConnectionStoreImpl, error) {
	store, err := ctx.StorageProvider().OpenStore(StoreName)
	if err != nil {
		return nil, err
	}

	return &ConnectionStoreImpl{
		store: store,
		vdr:   ctx.VDRegistry(),
	}, nil
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
