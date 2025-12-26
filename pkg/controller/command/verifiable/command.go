package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	modelverifiable "github.com/czh0526/aries-framework-go/component/models/verifiable"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	verifiablestore "github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	pverifiable "github.com/czh0526/aries-framework-go/provider/verifiable"
	"github.com/piprate/json-gold/ld"
)

type keyResolver interface {
	PublicKeyFetcher() didsignjwt.PublicKeyFetcher
}

var _ keyResolver = (*modelverifiable.VDRKeyResolver)(nil)

type Command struct {
	verifiableStore verifiablestore.Store
	didStore        *didstore.Store
	resolver        keyResolver
	ctx             pverifiable.Provider
	documentLoader  ld.DocumentLoader
}

func New(p pverifiable.Provider) (*Command, error) {
	verifiableStore, err := verifiablestore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vc store: %w", err)
	}

	didStore, err := didstore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new did store: %w", err)
	}

	return &Command{
		verifiableStore: verifiableStore,
		didStore:        didStore,
		resolver:        modelverifiable.NewVDRKeyResolver(p.VDRegistry()),
		ctx:             p,
		documentLoader:  p.JSONLDDocumentLoader(),
	}, nil
}
