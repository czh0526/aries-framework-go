package verifiable

import (
	verifiablestore "github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	pverifiable "github.com/czh0526/aries-framework-go/provider/verifiable"
)

type Command struct {
}

func New(p pverifiable.Provider) (*Command, error) {
	verifiableStore, err := verifiablestore.New(p)
}
