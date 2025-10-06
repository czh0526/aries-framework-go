package connection

import (
	"encoding/json"
	"fmt"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const (
	StateNameCompleted = "completed"
	MyNSPrefix         = "my"
	TheirNSPrefix      = "their"
	errMsgInvalidKey   = "invalid key"
)

type Recorder struct {
	*Lookup
}

func (r Recorder) SaveConnectionRecord(record *Record) error {
	err := marshalAndSave(getConnectionKeyPrefix()(record.ConnectionID), record,
		r.protocolStateStore,
		spistorage.Tag{
			Name:  getConnectionKeyPrefix()(""),
			Value: getConnectionKeyPrefix()(record.ConnectionID),
		})
	if err != nil {
		return fmt.Errorf("save connection record in protocol state store: %w", err)
	}

	if record.State != "" {
		err = marshalAndSave(getConnectionStateKeyPrefix()(record.ConnectionID, record.State), record,
			r.protocolStateStore,
			spistorage.Tag{
				Name:  connStateKeyPrefix,
				Value: getConnectionStateKeyPrefix()(record.ConnectionID),
			})
		if err != nil {
			return fmt.Errorf("save connection record with state in protocol state store: %w", err)
		}
	}

	if record.State == StateNameCompleted {
		err = marshalAndSave(getConnectionKeyPrefix()(record.ConnectionID), record,
			r.store,
			spistorage.Tag{
				Name:  getConnectionKeyPrefix()(""),
				Value: getConnectionKeyPrefix()(record.ConnectionID),
			},
			spistorage.Tag{
				Name:  bothDIDsTagName,
				Value: tagValueFromDIDs(record.MyDID, record.TheirDID),
			},
			spistorage.Tag{
				Name:  theirDIDTagName,
				Value: tagValueFromDIDs(record.TheirDID),
			})
		if err != nil {
			return fmt.Errorf("save connection record in permanent store: %w", err)
		}
	}

	return nil
}

func NewRecorder(p provider) (*Recorder, error) {
	lookup, err := NewLookup(p)
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection recorder: %w", err)
	}

	return &Recorder{lookup}, nil
}

func marshalAndSave(k string, v interface{}, store spistorage.Store, tags ...spistorage.Tag) error {
	bytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("save connection record: %w", err)
	}

	return store.Put(k, bytes, tags...)
}
