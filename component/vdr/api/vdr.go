package api

import (
	"errors"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
)

var ErrNotFound = errors.New("DID does not exist")

const (
	DIDCommServiceType = "didmodel-communication"

	DIDCommV2ServiceType = "DIDCommMessaging"

	LegacyServiceType = "IndyAgent"
)

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error)
	Create(method string, did *didmodel.Doc, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error)
	Update(did *didmodel.Doc, opts ...spivdr.DIDMethodOption) error
	Deactivate(did string, opts ...spivdr.DIDMethodOption) error
	Close() error
}

type VDR interface {
	Read(did string, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error)
	Create(did *didmodel.Doc, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error)
	Accept(method string, opts ...spivdr.DIDMethodOption) bool
	Update(did *didmodel.Doc, opts ...spivdr.DIDMethodOption) error
	Deactivate(did string, opts ...spivdr.DIDMethodOption) error
	Close() error
}
