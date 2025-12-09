package mock

import (
	"github.com/czh0526/aries-framework-go/component/models/ld/store"
	mockstorage "github.com/czh0526/aries-framework-go/component/storageutil/mock/storage"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/google/uuid"
)

type RemoteProviderStore struct {
	Store     *mockstorage.MockStore
	ErrGet    error
	ErrGetAll error
	ErrSave   error
	ErrDelete error
}

func NewMockRemoteProviderStore() *RemoteProviderStore {
	return &RemoteProviderStore{
		Store: &mockstorage.MockStore{
			Store: make(map[string]mockstorage.DBEntry),
		},
	}
}

func (s *RemoteProviderStore) Get(id string) (*store.RemoteProviderRecord, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	b, err := s.Store.Get(id)
	if err != nil {
		return nil, err
	}

	return &store.RemoteProviderRecord{
		ID:       id,
		Endpoint: string(b),
	}, nil
}

func (s *RemoteProviderStore) GetAll() ([]store.RemoteProviderRecord, error) {
	if s.ErrGetAll != nil {
		return nil, s.ErrGetAll
	}

	var records []store.RemoteProviderRecord
	for k, v := range s.Store.Store {
		records = append(records, store.RemoteProviderRecord{
			ID:       k,
			Endpoint: string(v.Value),
		})
	}

	return records, nil
}

func (s *RemoteProviderStore) Save(endpoint string) (*store.RemoteProviderRecord, error) {
	if s.ErrSave != nil {
		return nil, s.ErrSave
	}

	for k, v := range s.Store.Store {
		if string(v.Value) == endpoint {
			return &store.RemoteProviderRecord{
				ID:       k,
				Endpoint: string(v.Value),
			}, nil
		}
	}

	id := uuid.New().String()
	if err := s.Store.Put(id, []byte(endpoint), spistorage.Tag{
		Name: store.RemoteProviderRecordTag,
	}); err != nil {
		return nil, err
	}

	return &store.RemoteProviderRecord{
		ID:       id,
		Endpoint: endpoint,
	}, nil
}

func (s *RemoteProviderStore) Delete(id string) error {
	if s.ErrDelete != nil {
		return s.ErrDelete
	}

	return s.Store.Delete(id)
}
