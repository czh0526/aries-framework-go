package mock

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
)

type VDR struct {
	AcceptValue    bool
	StoreErr       error
	AcceptFunc     func(method string, opts ...spivdr.DIDMethodOption) bool
	ReadFunc       func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	CreateFunc     func(did *did.Doc, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	UpdateFunc     func(did *did.Doc, opts ...spivdr.DIDMethodOption) error
	DeactivateFunc func(didID string, opts ...spivdr.DIDMethodOption) error
	CloseErr       error
}

func (m *VDR) Read(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(didID, opts...)
	}

	return nil, nil
}

func (m *VDR) Accept(method string, opts ...spivdr.DIDMethodOption) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(method, opts...)
	}

	return m.AcceptValue
}

func (m *VDR) Create(did *did.Doc, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(did, opts...)
	}

	return nil, nil
}

func (m *VDR) Update(did *did.Doc, opts ...spivdr.DIDMethodOption) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(did, opts...)
	}

	return nil
}

func (m *VDR) Deactivate(didID string, opts ...spivdr.DIDMethodOption) error {
	if m.DeactivateFunc != nil {
		return m.DeactivateFunc(didID, opts...)
	}

	return nil
}

func (m *VDR) Close() error {
	return m.CloseErr
}
