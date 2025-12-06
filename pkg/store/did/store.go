package did

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const (
	NameSpace         = "didstore"
	didNameKey        = "didname_"
	didNameKeyPattern = didNameKey + "%s"
)

var logger = log.New("aries-framework/store/did")

type provider interface {
	StorageProvider() spistorage.Provider
}

type Store struct {
	store spistorage.Store
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

func (s *Store) SaveDID(name string, didDoc *didmodel.Doc) error {
	if name == "" {
		return errors.New("did name is mandatory")
	}

	id, err := s.GetDIDByName(name)
	if err != nil && !errors.Is(err, spistorage.ErrDataNotFound) {
		return fmt.Errorf("get did using name: %w", err)
	}

	if id != "" {
		return errors.New("did name already exists")
	}

	docytes, err := didDoc.JSONBytes()
	if err != nil {
		return fmt.Errorf("failed to marshal didDocL %w", err)
	}

	if err := s.store.Put(didDoc.ID, docytes); err != nil {
		return fmt.Errorf("failed to put didDoc: %w", err)
	}

	if err := s.store.Put(didNameDataKey(name), []byte(didDoc.ID), spistorage.Tag{Name: didNameKey}); err != nil {
		return fmt.Errorf("store did name to id map: %w", err)
	}

	return nil
}

func (s *Store) GetDID(id string) (*didmodel.Doc, error) {
	docBytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get did doc: %w", err)
	}

	didDoc, err := didmodel.ParseDocument(docBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling didDoc failed: %w", err)
	}

	return didDoc, nil
}

func (s *Store) GetDIDByName(name string) (string, error) {
	idBytes, err := s.store.Get(didNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("fetch did doc od based on name: %w", err)
	}

	return string(idBytes), nil
}

func (s *Store) GetDIDRecords() []*Record {
	itr, err := s.store.Query(didNameKey)
	if err != nil {
		return nil
	}

	defer func() {
		errClose := itr.Close()
		if errClose != nil {
			logger.Errorf("failed to close iterator: %w", errClose)
		}
	}()

	var records []*Record
	more, err := itr.Next()
	if err != nil {
		return nil
	}

	for more {
		name, err := itr.Key()
		if err != nil {
			return nil
		}

		id, err := itr.Value()
		if err != nil {
			return nil
		}

		records = append(records, &Record{
			Name: getDIDName(name),
			ID:   string(id),
		})
	}

	return records
}

func didNameDataKey(name string) string {
	return fmt.Sprintf(didNameKeyPattern, name)
}

func getDIDName(dataKey string) string {
	return dataKey[len(didNameKey):]
}
