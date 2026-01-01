package peer

import (
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
)

func (v *VDR) Read(didID string, _ ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
	doc, err := v.Get(didID)
	if err != nil {
		return nil, fmt.Errorf("fetching data from store failed: %w", err)
	}

	if doc == nil {
		return nil, vdrapi.ErrNotFound
	}

	return &didmodel.DocResolution{
		Context:     []string{schemaResV1},
		DIDDocument: doc,
	}, nil
}
