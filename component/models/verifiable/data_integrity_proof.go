package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/dataintegrity"
)

type verifyDataIntegrityOpts struct {
	Verifier  *dataintegrity.Verifier
	Purpose   string
	Domain    string
	Challenge string
}

func checkDataIntegrityProof(ldBytes []byte, opts *verifyDataIntegrityOpts) error {
	return fmt.Errorf("not implemented")
}
