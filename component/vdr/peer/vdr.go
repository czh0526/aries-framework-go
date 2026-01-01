package peer

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/did"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/czh0526/aries-framework-go/spi/vdr"
)

const (
	StoreNamespace = "peer"

	DefaultServiceType = "defaultServiceType"

	DefaultServiceEndpoint = "defaultServiceEndpoint"
)

type VDR struct {
	store spistorage.Store
}

func New(p spistorage.Provider) (*VDR, error) {
	didDBStore, err := p.OpenStore(StoreNamespace)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	return &VDR{
		store: didDBStore,
	}, nil
}

func (v *VDR) Accept(method string, opts ...vdr.DIDMethodOption) bool {
	return method == DIDMethod
}

func (v *VDR) Update(did *did.Doc, opts ...vdr.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (v *VDR) Deactivate(did string, opts ...vdr.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}
