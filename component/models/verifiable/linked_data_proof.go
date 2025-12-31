package verifiable

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	"github.com/czh0526/aries-framework-go/component/models/ld/proof"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	"github.com/czh0526/aries-framework-go/component/models/signature/signer"
	"time"
)

type SignatureRepresentation int

type LinkedDataProofContext struct {
	SignatureType           string
	Suite                   signer.SignatureSuite
	SignatureRepresentation SignatureRepresentation
	Created                 *time.Time
	VerificationMethod      string
	Challenge               string
	Domain                  string
	Purpose                 string
	CapabilityChain         []interface{}
}

type rawProof struct {
	Proof json.RawMessage `json:"proof,omitempty"`
}

func checkLinkedDataProof(jsonldBytes map[string]interface{}, suites []sigapi.SignatureSuite,
	pubKeyFetcher didsignjwt.PublicKeyFetcher, jsonldOpts *jsonldCredentialOpts) error {
	return fmt.Errorf("not implemented")
}

func addLinkedDataProof(context *LinkedDataProofContext, jsonldBytes []byte,
	opts ...ldprocessormodel.Opts) ([]Proof, error) {
	documentSigner := signer.New(context.Suite)

	vcWithNewProofBytes, err := documentSigner.Sign(
		mapContext(context), jsonldBytes, opts...)
	if err != nil {
		return nil, fmt.Errorf("add linked data proof: %w", err)
	}

	var rProof rawProof

	err = json.Unmarshal(vcWithNewProofBytes, &rProof)
	if err != nil {
		return nil, err
	}

	proofs, err := parseProof(rProof.Proof)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

func mapContext(context *LinkedDataProofContext) *signer.Context {
	return &signer.Context{
		SignatureType:           context.SignatureType,
		SignatureRepresentation: proof.SignatureRepresentation(context.SignatureRepresentation),
		Created:                 context.Created,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		Domain:                  context.Domain,
		Purpose:                 context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
}
