package didsignjwt

import (
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
)

type didResolver interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error)
}
