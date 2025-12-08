package suite

import "github.com/czh0526/aries-framework-go/component/models/dataintegrity/models"

type RequiresCreated interface {
	RequiresCreated() bool
}

type Verifier interface {
	VerifyProof(doc []byte, proof *models.Proof, opts *models.ProofOptions) error
	RequiresCreated
}
