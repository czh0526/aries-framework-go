package didsignjwt

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
)

type didResolver interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
}
