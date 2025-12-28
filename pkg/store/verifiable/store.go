package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	verifiablemodel "github.com/czh0526/aries-framework-go/component/models/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/store/verifiable/internal"
	pstore_verifiable "github.com/czh0526/aries-framework-go/provider/verifiable"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
)

const NameSpace = "verifiable"

var logger = log.New("aries-framework/store/verifiable")

type Opt func(o *options)

type options struct {
	MyDID    string
	TheirDID string
}

func WithMyDID(myDID string) Opt {
	return func(o *options) {
		o.MyDID = myDID
	}
}

func WithTheirDID(theirDID string) Opt {
	return func(o *options) {
		o.TheirDID = theirDID
	}
}

type Store interface {
	SaveCredential(name string, vc *verifiablemodel.Credential, opts ...Opt) error
	SavePresentation(name string, vp *verifiablemodel.Presentation, opts ...Opt) error
	GetCredential(id string) (*verifiablemodel.Credential, error)
	GetPresentation(id string) (*verifiablemodel.Presentation, error)
	GetCredentialIDByName(name string) (string, error)
	GetPresentationIDByName(name string) (string, error)
	GetCredentials() ([]*Record, error)
	GetPresentations() ([]*Record, error)
	RemoveCredentialByName(name string) error
	RemovePresentationByName(name string) error
}

type StoreImplementation struct {
	store          spistorage.Store
	documentLoader ld.DocumentLoader
}

func (s *StoreImplementation) SaveCredential(name string, vc *verifiablemodel.Credential, opts ...Opt) error {
	if name == "" {
		return errors.New("credential name is mandatory")
	}

	id, err := s.GetCredentialIDByName(name)
	if err != nil && !errors.Is(err, spistorage.ErrDataNotFound) {
		return fmt.Errorf("get credential id by name: %w", err)
	}

	if id != "" {
		return errors.New("credential with name `%s` already exists")
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}

	id = vc.ID
	if id == "" {
		id = uuid.New().String()
	}

	if e := s.store.Put(id, vcBytes); e != nil {
		return fmt.Errorf("failed to put vc: %w", e)
	}

	o := &options{}

	for _, opt := range opts {
		opt(o)
	}

	recordBytes, err := json.Marshal(&Record{
		ID:        id,
		Name:      name,
		Context:   vc.Context,
		Type:      vc.Types,
		MyDID:     o.MyDID,
		TheirDID:  o.TheirDID,
		SubjectID: getVCSubjectID(vc),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal credential record: %w", err)
	}

	return s.store.Put(internal.CredentialNameDataKey(name), recordBytes,
		spistorage.Tag{Name: internal.CredentialNameKey})
}

func (s StoreImplementation) SavePresentation(name string, vp *verifiablemodel.Presentation, opts ...Opt) error {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetCredential(id string) (*verifiablemodel.Credential, error) {
	vcBytes, err := s.store.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}

	vc, err := verifiablemodel.ParseCredential(vcBytes,
		verifiablemodel.WithDisabledProofCheck(),
		verifiablemodel.WithJSONLDDocumentLoader(s.documentLoader))
	if err != nil {
		return nil, fmt.Errorf("parse credential vc: %w", err)
	}

	return vc, nil
}

func (s StoreImplementation) GetPresentation(id string) (*verifiablemodel.Presentation, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetCredentialIDByName(name string) (string, error) {
	recordBytes, err := s.store.Get(internal.CredentialNameDataKey(name))
	if err != nil {
		return "", fmt.Errorf("failed to get credential id based on name: %w", err)
	}

	var r Record
	err = json.Unmarshal(recordBytes, &r)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal record: %w", err)
	}

	return r.ID, nil
}

func (s StoreImplementation) GetPresentationIDByName(name string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetCredentials() ([]*Record, error) {
	return s.getAllRecords(internal.CredentialNameDataKey(""))
}

func (s StoreImplementation) GetPresentations() ([]*Record, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) RemoveCredentialByName(name string) error {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) RemovePresentationByName(name string) error {
	//TODO implement me
	panic("implement me")
}

var _ Store = (*StoreImplementation)(nil)

func New(ctx pstore_verifiable.Provider) (*StoreImplementation, error) {
	store, err := ctx.StorageProvider().OpenStore(NameSpace)
	if err != nil {
		return nil, fmt.Errorf("failed to open vc store: %w", err)
	}

	err = ctx.StorageProvider().SetStoreConfig(NameSpace,
		spistorage.StoreConfiguration{
			TagNames: []string{internal.CredentialNameKey, internal.PresentationNameKey},
		})
	if err != nil {
		return nil, fmt.Errorf("failed to set vc store configuration: %w")
	}

	return &StoreImplementation{
		store:          store,
		documentLoader: ctx.JSONLDDocumentLoader(),
	}, nil
}

func (s *StoreImplementation) getAllRecords(searchKey string) ([]*Record, error) {
	iter, err := s.store.Query(searchKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query store: %w", err)
	}

	defer func() {
		errClose := iter.Close()
		if errClose != nil {
			logger.Errorf("failed to close iterator: %w", errClose)
		}
	}()

	var records []*Record

	more, err := iter.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to get next set of data from iterator")
	}

	for more {
		var r *Record

		value, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("failed to get value from iterator: %w", err)
		}

		err = json.Unmarshal(value, &r)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal record: %w", err)
		}

		records = append(records, r)

		more, err = iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to get next set of data from iterator: %w", err)
		}
	}

	return records, nil
}

func getVCSubjectID(vc *verifiablemodel.Credential) string {
	if subjectID, err := verifiablemodel.SubjectID(vc.Subject); err == nil {
		return subjectID
	}

	return ""
}
