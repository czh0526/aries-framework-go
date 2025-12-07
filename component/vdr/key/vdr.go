package key

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/spi/vdr"
)

const (
	DIDMethod     = "key"
	EncryptionKey = "encryptionKey"
)

type VDR struct {
}

func (V VDR) Accept(method string, opts ...vdr.DIDMethodOption) bool {
	return method == DIDMethod
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
	return nil
}

func New() *VDR {
	return &VDR{}
}
