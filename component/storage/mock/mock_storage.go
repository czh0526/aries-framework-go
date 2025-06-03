package mock

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/spi/storage"
	"strings"
	"sync"
)

var (
	errInvalidQueryExpressionFormat = errors.New(
		"invalid expression format. it must be in the following format: TagName:TagValue")
	errIteratorExhausted = errors.New("iterator is exhausted")
)

type DBEntry struct {
	Value []byte
	Tags  []storage.Tag
}

type MockStore struct {
	Store     map[string]DBEntry
	lock      sync.RWMutex
	ErrPut    error
	ErrGet    error
	ErrDelete error
	ErrQuery  error
	ErrNext   error
	ErrValue  error
	ErrKey    error
	ErrBatch  error
	ErrClose  error
}

func (m *MockStore) Put(key string, value []byte, tags ...storage.Tag) error {
	if key == "" {
		return errors.New("key is mandatory")
	}

	if m.ErrPut != nil {
		return m.ErrPut
	}

	m.lock.Lock()
	m.Store[key] = DBEntry{
		Value: value,
		Tags:  tags,
	}
	m.lock.Unlock()

	return m.ErrPut
}

func (m *MockStore) Get(key string) ([]byte, error) {
	if m.ErrGet != nil {
		return nil, m.ErrGet
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	entry, ok := m.Store[key]
	if !ok {
		return nil, storage.ErrDataNotFound
	}

	return entry.Value, m.ErrGet
}

func (m *MockStore) GetTags(key string) ([]storage.Tag, error) {
	panic("implement me")
}

func (m *MockStore) GetBulk(keys ...string) ([][]byte, error) {
	panic("implement me")
}

func (m *MockStore) Query(expression string, options ...storage.QueryOption) (storage.Iterator, error) {
	if m.ErrQuery != nil {
		return nil, m.ErrQuery
	}

	if expression == "" {
		return nil, errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ":")
	switch len(expressionSplit) {
	case 1:
		expressionTagName := expressionSplit[0]

		m.lock.RLock()
		defer m.lock.RUnlock()

		keys, dbEntries := m.getMatchingKeysAndDBEntries(expressionTagName, "")
		return &iterator{
			keys:      keys,
			dbEntries: dbEntries,
			errNext:   m.ErrNext,
			errValue:  m.ErrValue,
			errKey:    m.ErrKey,
		}, nil

	case 2:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		m.lock.RLock()
		defer m.lock.RUnlock()

		keys, dbEntries := m.getMatchingKeysAndDBEntries(expressionTagName, expressionTagValue)
		return &iterator{
			keys:      keys,
			dbEntries: dbEntries,
			errNext:   m.ErrNext,
			errValue:  m.ErrValue,
			errKey:    m.ErrKey,
		}, nil

	default:
		return nil, errInvalidQueryExpressionFormat
	}
}

func (m *MockStore) Delete(key string) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.Store, key)

	return m.ErrDelete
}

func (m *MockStore) Batch(operations []storage.Operation) error {
	if m.ErrBatch != nil {
		return m.ErrBatch
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	for _, op := range operations {
		m.Store[op.Key] = DBEntry{
			Value: op.Value,
			Tags:  op.Tags,
		}
	}

	return nil
}

func (m *MockStore) Flush() error {
	panic("implement me")
}

func (m *MockStore) Close() error {
	return m.ErrClose
}

func (m *MockStore) getMatchingKeysAndDBEntries(tagName, tagValue string) ([]string, []DBEntry) {
	var matchAnyValue bool
	if tagValue == "" {
		matchAnyValue = true
	}

	var keys []string
	var dbEntries []DBEntry
	for key, dbEntry := range m.Store {
		for _, tag := range dbEntry.Tags {
			if tag.Name == tagName && (matchAnyValue || tag.Value == tagValue) {
				keys = append(keys, key)
				dbEntries = append(dbEntries, dbEntry)

				break
			}
		}
	}

	return keys, dbEntries
}

type iterator struct {
	currentIndex   int
	currentKey     string
	currentDBEntry DBEntry
	keys           []string
	dbEntries      []DBEntry
	errNext        error
	errValue       error
	errKey         error
}

func (i *iterator) Tags() ([]storage.Tag, error) {
	if len(i.dbEntries) == 0 {
		return nil, errIteratorExhausted
	}
	return i.currentDBEntry.Tags, nil
}

func (i *iterator) TotalItems() (int, error) {
	return -1, errors.New("not implemented")
}

func (i *iterator) Close() error {
	return nil
}

func (i *iterator) Next() (bool, error) {
	if i.errNext != nil {
		return false, i.errNext
	}

	if len(i.dbEntries) == i.currentIndex || len(i.dbEntries) == 0 {
		i.dbEntries = nil
		return false, nil
	}

	i.currentKey = i.keys[i.currentIndex]
	i.currentDBEntry = i.dbEntries[i.currentIndex]
	i.currentIndex++

	return true, nil
}

func (i *iterator) Key() (string, error) {
	if i.errKey != nil {
		return "", i.errKey
	}

	if len(i.dbEntries) == 0 {
		return "", errIteratorExhausted
	}

	return i.currentKey, nil
}

func (i *iterator) Value() ([]byte, error) {
	if i.errValue != nil {
		return nil, i.errValue
	}

	if len(i.dbEntries) == 0 {
		return nil, errIteratorExhausted
	}

	return i.currentDBEntry.Value, nil
}

type MockStoreProvider struct {
	Store              *MockStore
	Custom             storage.Store
	ErrOpenStoreHandle error
	ErrSetStoreConfig  error
	ErrClose           error
	ErrCloseStore      error
	FailNamespace      string
}

func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{
		Store: &MockStore{
			Store: make(map[string]DBEntry),
		},
	}
}

func NewCustomMockStoreProvider(customStore storage.Store) *MockStoreProvider {
	return &MockStoreProvider{
		Custom: customStore,
	}
}

func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	if name == s.FailNamespace {
		return nil, fmt.Errorf("failed to open store for namespace %s", name)
	}

	if s.Custom != nil {
		return s.Custom, s.ErrOpenStoreHandle
	}

	return s.Store, s.ErrOpenStoreHandle
}

func (s *MockStoreProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	return s.ErrSetStoreConfig
}

func (s *MockStoreProvider) GetStoreConfig(name string) (storage.StoreConfiguration, error) {
	panic("implement me")
}

func (s *MockStoreProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

func (s *MockStoreProvider) Close() error {
	//TODO implement me
	panic("implement me")
}
