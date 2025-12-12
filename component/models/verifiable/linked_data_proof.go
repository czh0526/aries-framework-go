package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
)

func checkLinkedDataProof(jsonldBytes map[string]interface{}, suites []sigapi.SignatureSuite,
	pubKeyFetcher didsignjwt.PublicKeyFetcher, jsonldOpts *jsonldCredentialOpts) error {
	return fmt.Errorf("not implemented")
}
