package storage

import (
	"errors"
	"fmt"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"strings"
	"sync"
)

const (
	expressionTagNameOnlyLength     = 1
	expressionTagNameAndValueLength = 2
)

var (
	errInvalidQueryExpressionFormat = errors.New(
		"invalid query expression. it must be in the following format: TagName:TagValue")
	errIteratorExhausted = errors.New("iterator is exhausted")
)

type MockStoreProvider struct {
	Store              *MockStore
	Custom             spistorage.Store
	ErrOpenStoreHandle error
	ErrSetStoreConfig  error
	ErrClose           error
	ErrCloseStore      error
	FailNamespace      string
}

func (p *MockStoreProvider) OpenStore(name string) (spistorage.Store, error) {
	if name == p.FailNamespace {
		return nil, fmt.Errorf("failed to open store for name space: %p", name)
	}

	if p.Custom != nil {
		return p.Custom, p.ErrOpenStoreHandle
	}

	return p.Store, p.ErrOpenStoreHandle
}

func (p *MockStoreProvider) SetStoreConfig(name string, config spistorage.StoreConfiguration) error {
	return p.ErrSetStoreConfig
}

func (p *MockStoreProvider) GetStoreConfig(name string) (spistorage.StoreConfiguration, error) {
	panic("implement me")
}

func (p *MockStoreProvider) GetOpenStores() []spistorage.Store {
	panic("implement me")
}

func (p *MockStoreProvider) Close() error {
	return p.ErrClose
}

var _ spistorage.Provider = (*MockStoreProvider)(nil)

func NewMockStoreProvider() *MockStoreProvider {
	return &MockStoreProvider{
		Store: &MockStore{
			Store: make(map[string]DBEntry),
		},
	}
}

func NewCustomMockStoreProvider(customStore spistorage.Store) *MockStoreProvider {
	return &MockStoreProvider{
		Custom: customStore,
	}
}

type DBEntry struct {
	Value []byte
	Tags  []spistorage.Tag
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

func (s *MockStore) Put(key string, value []byte, tags ...spistorage.Tag) error {
	if key == "" {
		return errors.New("key is mandatory")
	}

	if s.ErrPut != nil {
		return s.ErrPut
	}

	s.lock.Lock()
	s.Store[key] = DBEntry{
		Value: value,
		Tags:  tags,
	}
	s.lock.Unlock()

	return s.ErrPut
}

func (s *MockStore) Get(key string) ([]byte, error) {
	if s.ErrGet != nil {
		return nil, s.ErrGet
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	entry, ok := s.Store[key]
	if !ok {
		return nil, spistorage.ErrDataNotFound
	}

	return entry.Value, nil
}

func (s *MockStore) GetTags(key string) ([]spistorage.Tag, error) {
	//TODO implement me
	panic("implement me")
}

func (s *MockStore) GetBulk(keys ...string) ([][]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s *MockStore) Query(expression string, options ...spistorage.QueryOption) (spistorage.Iterator, error) {
	if s.ErrQuery != nil {
		return nil, s.ErrQuery
	}

	if expression == "" {
		return nil, errInvalidQueryExpressionFormat
	}

	expressionSplit := strings.Split(expression, ".")
	switch len(expressionSplit) {
	case expressionTagNameOnlyLength:
		expressionTagName := expressionSplit[0]

		s.lock.RLock()
		defer s.lock.RUnlock()

		keys, dbEntries := s.getMatchingKeysAndDBEntries(expressionTagName, "")

		return &iterator{
			keys:      keys,
			dbEntries: dbEntries,
			errNext:   s.ErrNext,
			errValue:  s.ErrValue,
			errKey:    s.ErrKey,
		}, nil

	case expressionTagNameAndValueLength:
		expressionTagName := expressionSplit[0]
		expressionTagValue := expressionSplit[1]

		s.lock.RLock()
		defer s.lock.RUnlock()

		keys, dbEntries := s.getMatchingKeysAndDBEntries(expressionTagName, expressionTagValue)

		return &iterator{
			keys:      keys,
			dbEntries: dbEntries,
			errNext:   s.ErrNext,
			errValue:  s.ErrValue,
			errKey:    s.ErrKey,
		}, nil

	default:
		return nil, errInvalidQueryExpressionFormat
	}
}

func (s *MockStore) Delete(key string) error {
	s.lock.Lock()
	delete(s.Store, key)
	s.lock.Unlock()

	return s.ErrDelete
}

func (s *MockStore) Batch(operations []spistorage.Operation) error {
	if s.ErrBatch != nil {
		return s.ErrBatch
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	for _, op := range operations {
		s.Store[op.Key] = DBEntry{
			Value: op.Value,
			Tags:  op.Tags,
		}
	}

	return nil
}

func (s *MockStore) Flush() error {
	//TODO implement me
	panic("implement me")
}

func (s *MockStore) Close() error {
	return s.ErrClose
}

func (s *MockStore) getMatchingKeysAndDBEntries(tagName, tagValue string) ([]string, []DBEntry) {
	var matchAnyValue bool
	if tagValue == "" {
		matchAnyValue = true
	}

	var keys []string
	var dbEntries []DBEntry

	for key, entry := range s.Store {
		for _, tag := range entry.Tags {
			if tag.Name == tagName && (matchAnyValue || tag.Value == tagValue) {
				keys = append(keys, key)
				dbEntries = append(dbEntries, entry)

				break
			}
		}
	}

	return keys, dbEntries
}

var _ spistorage.Store = (*MockStore)(nil)

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

func (i *iterator) Tags() ([]spistorage.Tag, error) {
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

var _ spistorage.Iterator = (*iterator)(nil)
