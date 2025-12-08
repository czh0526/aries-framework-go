package verifiable

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/store/verifiable/internal"
	pstore_verifiable "github.com/czh0526/aries-framework-go/provider/verifiable"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
)

const NameSpace = "verifiable"

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
	SaveCredential(name string, vc *verifiable.Credential, opts ...Opt) error
	SavePresentation(name string, vp *verifiable.Presentation, opts ...Opt) error
	GetCredential(id string) (*verifiable.Credential, error)
	GetPresentation(id string) (*verifiable.Presentation, error)
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

func (s *StoreImplementation) SaveCredential(name string, vc *verifiable.Credential, opts ...Opt) error {
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

	record := &internal.Record{
		Name:      name,
		ID:        id,
		Context:   vc.Context,
		Type:      vc.Types,
		SubjectID: vc.Subject.ID,
		MyDID:     opts[0].MyDID,
		TheirDID:  opts[0].TheirDID,
	}

	err = s.store.Put(id, vcBytes, spistorage.Tag{Name: internal.CredentialNameKey, Value: name})
	if err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	err = s.store.Put(name, record, spistorage.Tag{Name: internal.CredentialNameKey, Value: name})
	if err != nil {
		return fmt.Errorf("save credential record: %w", err)
	}

	return nil
}

func (s StoreImplementation) SavePresentation(name string, vp *verifiable.Presentation, opts ...Opt) error {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetCredential(id string) (*verifiable.Credential, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetPresentation(id string) (*verifiable.Presentation, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetCredentialIDByName(name string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetPresentationIDByName(name string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (s StoreImplementation) GetCredentials() ([]*Record, error) {
	//TODO implement me
	panic("implement me")
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
