package api

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
)

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Create(method string, did *did.Doc, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Update(did *did.Doc, opts ...spivdr.DIDMethodOption) error
	Deactivate(did string, opts ...spivdr.DIDMethodOption) error
	Close() error
}

type VDR interface {
	Read(did string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Create(did *did.Doc, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Accept(method string, opts ...spivdr.DIDMethodOption) bool
	Update(did *did.Doc, opts ...spivdr.DIDMethodOption) error
	Deactivate(did string, opts ...spivdr.DIDMethodOption) error
	Close() error
}
