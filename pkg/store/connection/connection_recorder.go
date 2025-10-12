package connection

import (
	"crypto"
	"encoding/json"
	"errors"
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

func (r *Recorder) SaveConnectionRecord(record *Record) error {
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

func (r *Recorder) SaveConnectionRecordWithMappings(record *Record) error {
	err := isValidConnection(record)
	if err != nil {
		return fmt.Errorf("validation faild while saving connction record with mappings: %w", err)
	}

	err = r.SaveConnectionRecord(record)
	if err != nil {
		return fmt.Errorf("failed to save connection record with mappings: %w", err)
	}

	err = r.SaveNamespaceThreadID(record.ThreadID, record.Namespace, record.ConnectionID)
	if err != nil {
		return fmt.Errorf("failed to save connection record with namespace mappings: %w", err)
	}

	return nil
}

func (r *Recorder) SaveInvitation(id string, invitation interface{}) error {
	if id == "" {
		return fmt.Errorf(errMsgInvalidKey)
	}

	return marshalAndSave(getInvitationKeyPrefix()(id), invitation, r.store)
}

func (r *Recorder) SaveNamespaceThreadID(threadID, namespace, connectionID string) error {
	if namespace != MyNSPrefix && namespace != TheirNSPrefix {
		return fmt.Errorf("namespace not supported")
	}

	prefix := MyNSPrefix
	if namespace == TheirNSPrefix {
		prefix = TheirNSPrefix
	}

	key, err := computeHash([]byte(threadID))
	if err != nil {
		return err
	}

	return r.protocolStateStore.Put(getNamespaceKeyPrefix(prefix)(key), []byte(connectionID))
}

func (r *Recorder) SaveEvent(connectionID string, data []byte) error {
	return r.protocolStateStore.Put(getEventDataKeyPrefix()(connectionID), data)
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

func computeHash(bytes []byte) (string, error) {
	if len(bytes) == 0 {
		return "", errors.New("unable to compute hash, empty bytes")
	}

	h := crypto.SHA256.New()
	hash := h.Sum(bytes)

	return fmt.Sprintf("%x", hash), nil
}

func isValidConnection(r *Record) error {
	if r.ThreadID == "" || r.ConnectionID == "" || r.Namespace == "" {
		return fmt.Errorf("input parameters thid : %s, and connectionId : %s namespace : %s cannot be empty",
			r.ThreadID, r.ConnectionID, r.Namespace)
	}

	return nil
}
