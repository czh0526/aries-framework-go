package key

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/spi/vdr"
)

type VDR struct {
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

func New() *VDR {
	return &VDR{}
}
