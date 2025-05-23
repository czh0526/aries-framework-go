package store

import spistorage "github.com/czh0526/aries-framework-go/spi/storage"

type RemoteProviderStoreImpl struct {
	store               spistorage.Store
	debugDisableBackoff bool
}

func (r RemoteProviderStoreImpl) Get(id string) (*RemoteProviderRecord, error) {
	//TODO implement me
	panic("implement me")
}

func (r RemoteProviderStoreImpl) GetAll() ([]RemoteProviderRecord, error) {
	//TODO implement me
	panic("implement me")
}

func (r RemoteProviderStoreImpl) Save(endpoint string) (*RemoteProviderRecord, error) {
	//TODO implement me
	panic("implement me")
}

func (r RemoteProviderStoreImpl) Delete(id string) error {
	//TODO implement me
	panic("implement me")
}
