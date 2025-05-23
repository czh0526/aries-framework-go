package storage

import "errors"

// MultiError represents the errors that occurred during a bulk operation.
type MultiError interface {
	error
	Errors() []error // Errors returns the error objects for all operations.
}

var (
	// ErrStoreNotFound is returned when a store is not found.
	ErrStoreNotFound = errors.New("store not found")
	// ErrDataNotFound is returned when data is not found.
	ErrDataNotFound = errors.New("data not found")
	// ErrDuplicateKey is returned when a call is made to Store.Batch using the IsNewKey PutOption with a key that
	// already exists in the database.
	ErrDuplicateKey = errors.New("duplicate key")
)

type StoreConfiguration struct {
	TagNames []string `json:"tagNames,omitempty"`
}

type Tag struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type SortOrder int

const (
	SortAscending SortOrder = iota
	SortDescending
)

type SortOptions struct {
	Order   SortOrder
	TagName string
}

type QueryOptions struct {
	PageSize       int
	InitialPageNum int
	SortOptions    *SortOptions
}

type QueryOption func(opts *QueryOptions)

func WithPageSize(size int) QueryOption {
	return func(opts *QueryOptions) {
		opts.PageSize = size
	}
}

func WithInitialPageNum(initialPageNum int) QueryOption {
	return func(opts *QueryOptions) {
		opts.InitialPageNum = initialPageNum
	}
}

func WithSortOrder(sortOptions *SortOptions) QueryOption {
	return func(opts *QueryOptions) {
		opts.SortOptions = sortOptions
	}
}

type PutOptions struct {
	IsNewKey bool `json:"isNewKey,omitempty"`
}

type Operation struct {
	Key        string      `json:"key,omitempty"`
	Value      []byte      `json:"value,omitempty"`
	Tags       []Tag       `json:"tags,omitempty"`
	PutOptions *PutOptions `json:"putOptions,omitempty"`
}

// Provider represents a storage provider.
type Provider interface {
	// OpenStore opens a Store with the given name and returns it.
	// Depending on the store implementation, this may or may not create an underlying database.
	// The store implementation may defer creating the underlying database until SetStoreConfig is called or
	// data is inserted using Store.Put or Store.Batch.
	// Store names are not case-sensitive. If name is blank, then an error will be returned.
	OpenStore(name string) (Store, error)

	// SetStoreConfig sets the configuration on a Store. It's recommended calling this method at some point before
	// calling Store.Query if your store contains a large amount of data. The underlying database will use this to
	// create indexes to make querying via the Store.Query method faster. If you don't need to use Store.Query, then
	// you don't need to call this method. OpenStore must be called first before calling this method. If not, then an
	// error wrapping ErrStoreNotFound will be returned. This method will not open the store automatically.
	// If name is blank, then an error will be returned.
	SetStoreConfig(name string, config StoreConfiguration) error

	// GetStoreConfig gets the current Store configuration.
	// This method operates a bit differently in that it directly checks the underlying storage implementation to see
	// if the underlying database exists for the given name, rather than checking the currently known list of
	// open stores in memory. If no underlying database can be found, then an error wrapping ErrStoreNotFound will be
	// returned. This means that this method can be used to determine whether an underlying database for a Store
	// already exists or not. This method will not create the database automatically.
	// If name is blank, then an error will be returned.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetStoreConfig(name string) (StoreConfiguration, error)

	// GetOpenStores returns all Stores that are currently open in memory from calling OpenStore.
	// It does not check for all databases that have been created before. They have to have been opened in this Provider
	// object's lifetime from a call to OpenStore.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetOpenStores() []Store

	// Close closes all open Stores in this Provider
	// For persistent Store implementations, this does not delete any data in the underlying databases.
	Close() error
}

type Store interface {
	// Put stores the key + value pair along with the (optional) tags. If the key already exists in the database,
	// then the value and tags will be overwritten silently.
	// If value is a JSON-formatted object, then an underlying storage implementation may store it in a way that
	// does not preserve the order of the fields. Therefore, you should avoid doing direct byte-for-byte comparisons
	// with data put in and data retrieved, as the marshalled representation may be different - always unmarshal data
	// first before comparing.
	// If key is empty or value is nil, then an error will be returned.
	// A single key-value pair cannot have multiple tags that share the same tag name.
	Put(key string, value []byte, tags ...Tag) error

	// Get fetches the value associated with the given key.
	// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
	// If key is empty, then an error will be returned.
	Get(key string) ([]byte, error)

	// GetTags fetches all tags associated with the given key.
	// If key cannot be found, then an error wrapping ErrDataNotFound will be returned.
	// If key is empty, then an error will be returned.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetTags(key string) ([]Tag, error)

	// GetBulk fetches the values associated with the given keys.
	// If no data exists under a given key, then a nil []byte is returned for that value. It is not considered an error.
	// Depending on the implementation, this method may be faster than calling Get for each key individually.
	// If any of the given keys are empty, then an error will be returned.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	GetBulk(keys ...string) ([][]byte, error)

	// Query returns all data that satisfies the expression. Basic expression format: TagName:TagValue.
	// If TagValue is not provided, then all data associated with the TagName will be returned, regardless of their
	// tag values.
	// At a minimum, a store implementation must be able to support querying with a single basic expression, but a
	// store implementation may also support a more advanced expression format.
	// Advanced expression format: [Criterion1][Operator][Criterion2][Operator]...[CriterionN]. Square brackets are
	// used here for visual clarity. Omit them from the actual expression string.
	// Each Criterion follows the rules for the basic expression format described above.
	// Each operator must be either "&&" or "||" (without quotes). "&&" indicates an AND operator while "||"
	// indicates an OR operator. The order of operations are ANDs followed by ORs.
	// This method also supports a number of QueryOptions. If none are provided, then defaults will be used.
	// If your store contains a large amount of data, then it's recommended calling Provider.SetStoreConfig at some
	// point before calling this method in order to create indexes which will speed up queries.
	Query(expression string, options ...QueryOption) (Iterator, error)

	// Delete deletes the key + value pair (and all tags) associated with key.
	// If key is empty, then an error will be returned.
	Delete(key string) error

	// Batch performs multiple Put and/or Delete operations in order. The Puts and Deletes here follow the same rules
	// as described in the Put and Delete method documentation. The only exception is if the operation makes use of
	// the PutOptions.IsNewKey optimization, in which case an error wrapping an ErrDuplicateKey may be returned if it's
	// enabled and a key is used that already exists in the database.
	// Depending on the implementation, this method may be faster than repeated Put and/or Delete calls.
	// If any of the given keys are empty, or the operations slice is empty or nil, then an error will be returned.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	Batch(operations []Operation) error

	// Flush forces any queued up Put and/or Delete operations to execute.
	// If the Store implementation doesn't queue up operations, then this method is a no-op.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	Flush() error

	// Close closes this store object, freeing resources. For persistent store implementations, this does not delete
	// any data in the underlying databases.
	// Close can be called repeatedly on the same store multiple times without causing an error.
	Close() error
}

// Iterator allows for iteration over a collection of entries in a store.
type Iterator interface {
	// Next moves the pointer to the next entry in the iterator.
	// Note that it must be called before accessing the first entry.
	// It returns false if the iterator is exhausted - this is not considered an error.
	Next() (bool, error)

	// Key returns the key of the current entry.
	Key() (string, error)

	// Value returns the value of the current entry.
	Value() ([]byte, error)

	// Tags returns the tags associated with the key of the current entry.
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	Tags() ([]Tag, error)

	// TotalItems returns a count of the number of entries (key + value + tags triplets) matched by the query
	// that generated this Iterator. This count is not affected by the page settings used (i.e. the count is of all
	// results as if you queried starting from the first page and with an unlimited page size).
	// Depending on the storage implementation, you may need to ensure that the TagName used in the query is in the
	// Store's StoreConfiguration before trying to call this method (or it may be optional, but recommended).
	// As of writing, aries-framework-go code does not use this, but it may be useful for custom solutions.
	TotalItems() (int, error)

	// Close closes this iterator object, freeing resources.
	Close() error
}
