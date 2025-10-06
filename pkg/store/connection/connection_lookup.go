package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	did_endpoint "github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	did_comm "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"strings"
)

const (
	Namespace          = "didexchange"
	keyPattern         = "%s_%s"
	connIDKeyPrefix    = "conn"
	connStateKeyPrefix = "connstate"
	bothDIDsTagName    = "bothDIDs"
	theirDIDTagName    = "theirDID"
	invKeyPrefix       = "inv"
	oobV2InvKeyPrefix  = "oobs"
	eventDataKeyPrefix = "connevent"
	keySeparator       = "_"
	stateIDEmptyErr    = "stateID can't be empty"
)

var logger = log.New("aries-framework/store/connection")

type KeyPrefix func(...string) string

type provider interface {
	ProtocolStateStorageProvider() spistorage.Provider
	StorageProvider() spistorage.Provider
}

type DIDRotationRecord struct {
	OldDID    string `json:"oldDID,omitempty"`
	NewDID    string `json:"newDID,omitempty"`
	FromPrior string `json:"fromPrior,omitempty"`
}

type Record struct {
	ConnectionID            string
	State                   string
	ThreadID                string
	ParentThreadID          string
	TheirLabel              string
	TheirDID                string
	MyDID                   string
	ServiceEndPoint         did_endpoint.Endpoint
	RecipientKeys           []string
	RoutingKeys             []string
	InvitationID            string
	InvitationDID           string
	InvitationRecipientKeys []string `json:"invitationRecipientKeys,omitempty"`
	Implicit                bool
	Namespace               string
	MediaTypeProfiles       []string
	DIDCommVersion          did_comm.Version
	PeerDIDInitialState     string
	MyDIDRotation           *DIDRotationRecord `json:"myDIDRotation,omitempty"`
}

type Lookup struct {
	protocolStateStore spistorage.Store
	store              spistorage.Store
}

func (c *Lookup) GetConnectionIDByDIDs(myDID, theirDID string) (string, error) {
	record, err := c.GetConnectionRecordByDIDs(myDID, theirDID)
	if err != nil {
		return "", fmt.Errorf("get connection record by DIDs: %w", err)
	}

	return record.ConnectionID, nil
}

func (c *Lookup) GetConnectionRecord(connectionID string) (*Record, error) {
	var rec Record

	err := getAndUnmarshal(getConnectionKeyPrefix()(connectionID), &rec, c.store)
	if err != nil {
		if errors.Is(err, spistorage.ErrDataNotFound) {
			err = getAndUnmarshal(getConnectionKeyPrefix()(connectionID), &rec, c.protocolStateStore)
			if err != nil {
				return nil, err
			} else {
				return nil, err
			}
		}
	}

	return &rec, nil
}

func (c *Lookup) GetConnectionRecordByDIDs(myDID, theirDID string) (*Record, error) {
	return c.queryExpectingOne(bothDIDsTagName+":"+tagValueFromDIDs(myDID, theirDID), c.store)
}

func (c *Lookup) GetConnectionRecordByTheirDID(theirDID string) (*Record, error) {
	return c.queryExpectingOne(theirDIDTagName+":"+tagValueFromDIDs(theirDID), c.store)
}

func (c *Lookup) queryExpectingOne(query string, store spistorage.Store) (*Record, error) {
	records, err := queryRecordsFromStore(query, store, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get data from persistent store: %w", err)
	}

	if len(records) == 0 {
		return nil, spistorage.ErrDataNotFound
	}

	logger.Debugf("query '%s' expected 1 result, got %d", query, len(records))

	return records[0], nil
}

func (c *Lookup) GetOOBv2Invitation(myDID string, target interface{}) error {
	if myDID == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return getAndUnmarshal(getOOBInvitationV2KeyPrefix()(tagValueFromDIDs(myDID)), target, c.store)
}

func NewLookup(p provider) (*Lookup, error) {
	store, err := p.StorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open parmanent store to create new connection recorder: %w", err)
	}

	err = p.StorageProvider().SetStoreConfig(Namespace, spistorage.StoreConfiguration{
		TagNames: []string{
			connIDKeyPrefix,
			bothDIDsTagName,
			theirDIDTagName,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config in permanent store: %w", err)
	}

	protocolStateStore, err := p.ProtocolStateStorageProvider().OpenStore(Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open protocol state store to create new connection recorder: %w", err)
	}

	err = p.ProtocolStateStorageProvider().SetStoreConfig(Namespace, spistorage.StoreConfiguration{
		TagNames: []string{
			connIDKeyPrefix,
			connStateKeyPrefix,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set store config in protocol state store: %w", err)
	}

	return &Lookup{
		protocolStateStore: protocolStateStore,
		store:              store,
	}, nil
}

func getAndUnmarshal(key string, target interface{}, store spistorage.Store) error {
	bytes, err := store.Get(key)
	if err != nil {
		return err
	}

	err = json.Unmarshal(bytes, target)
	if err != nil {
		return err
	}

	return nil
}

func getConnectionKeyPrefix() KeyPrefix {
	return func(keys ...string) string {
		return fmt.Sprintf(keyPattern, connIDKeyPrefix, strings.Join(keys, keySeparator))
	}
}

func getConnectionStateKeyPrefix() KeyPrefix {
	return func(keys ...string) string {
		return fmt.Sprintf(keyPattern, connStateKeyPrefix, strings.Join(keys, keySeparator))
	}
}

func getOOBInvitationV2KeyPrefix() KeyPrefix {
	return func(key ...string) string {
		return fmt.Sprintf(keyPattern, oobV2InvKeyPrefix, strings.Join(key, keySeparator))
	}
}

func tagValueFromDIDs(dids ...string) string {
	for i, did := range dids {
		dids[i] = strings.ReplaceAll(did, ":", "$")
	}

	return strings.Join(dids, "|")
}

func queryRecordsFromStore(searchKey string, store spistorage.Store, usedKeys map[string]struct{}, appendTo []*Record) (
	[]*Record, error) {
	if usedKeys == nil {
		usedKeys = make(map[string]struct{})
	}

	iter, err := store.Query(searchKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query records from store: %w", err)
	}
	defer func() {
		errClose := iter.Close()
		if errClose != nil {
			logger.Errorf("failed to close records iterator: %s", errClose.Error())
		}
	}()

	appendTo, err = readRecordIterator(iter, usedKeys, appendTo)
	if err != nil {
		return nil, fmt.Errorf("failed to read records from iterator: %w", err)
	}

	return appendTo, nil
}

// readRecordIterator 将 iterator 中的 Record 读入 appendTo，补充到 usedKeys
func readRecordIterator(iter spistorage.Iterator, usedKeys map[string]struct{}, appendTo []*Record) (
	[]*Record, error) {
	var (
		more    bool
		errNext error
	)

	for more, errNext = iter.Next(); more && errNext == nil; more, errNext = iter.Next() {
		key, err := iter.Key()
		if err != nil {
			return nil, fmt.Errorf("failed to get key from iterator: %w", err)
		}

		if _, ok := usedKeys[key]; ok {
			continue
		}

		value, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from iterator: %w", err)
		}

		var record Record

		err = json.Unmarshal(value, &record)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal connection record: %w", err)
		}

		appendTo = append(appendTo, &record)
		usedKeys[key] = struct{}{}
	}

	if errNext != nil {
		return nil, fmt.Errorf("failed to get next set of data from iterator: %w", errNext)
	}

	return appendTo, nil
}
