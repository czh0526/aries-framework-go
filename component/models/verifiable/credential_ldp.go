package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/ld/processor"
)

func (vc *Credential) AddLinkedDataProof(context *LinkedDataProofContext, jsonldOpts ...processor.Opts) error {
	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return fmt.Errorf("add linked data proof to VC: %w", err)
	}

	proofs, err := addLinkedDataProof(context, vcBytes, jsonldOpts...)
	if err != nil {
		return err
	}

	vc.Proofs = proofs
	return nil
}
