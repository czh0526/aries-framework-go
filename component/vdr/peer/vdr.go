package peer

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/did"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/czh0526/aries-framework-go/spi/vdr"
)

const (
	StoreNamespace = "peer"
)

type VDR struct {
	store spistorage.Store
}

func (V VDR) Read(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	//TODO implement me
	panic("implement me")
}

func (V VDR) Create(did *did.Doc, opts ...vdr.DIDMethodOption) (*did.DocResolution, error) {
	//TODO implement me
	panic("implement me")
}

func (V VDR) Accept(method string, opts ...vdr.DIDMethodOption) bool {
	//TODO implement me
	panic("implement me")
}

func (V VDR) Update(did *did.Doc, opts ...vdr.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (V VDR) Deactivate(did string, opts ...vdr.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (V VDR) Close() error {
	//TODO implement me
	panic("implement me")
}

func New(p spistorage.Provider) (*VDR, error) {
	didDBStore, err := p.OpenStore(StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("open store: %v", err)
	}

	return &VDR{
		store: didDBStore,
	}, nil
}
