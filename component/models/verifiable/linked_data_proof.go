package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
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

func checkLinkedDataProof(jsonldBytes map[string]interface{}, suites []sigapi.SignatureSuite,
	pubKeyFetcher didsignjwt.PublicKeyFetcher, jsonldOpts *jsonldCredentialOpts) error {
	return fmt.Errorf("not implemented")
}
