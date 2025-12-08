package verifiable

import "github.com/czh0526/aries-framework-go/component/models/dataintegrity"

type verifyDataIntegrityOpts struct {
	Verifier  *dataintegrity.Verifier
	Purpose   string
	Domain    string
	Challenge string
}
