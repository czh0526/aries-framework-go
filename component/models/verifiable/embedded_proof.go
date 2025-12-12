package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/dataintegrity/models"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	jsonld "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
)

type embeddedProofCheckOpts struct {
	jsonldCredentialOpts

	publicKeyFetcher   didsignjwt.PublicKeyFetcher
	disabledProofCheck bool
	ldpSuites          []sigapi.SignatureSuite
	dataIntegrityOpts  *verifyDataIntegrityOpts
}

func getEmbeddedProofCheckOpts(vcOpts *credentialOpts) *embeddedProofCheckOpts {
	return &embeddedProofCheckOpts{
		jsonldCredentialOpts: vcOpts.jsonldCredentialOpts,
		publicKeyFetcher:     vcOpts.publicKeyFetcher,
		disabledProofCheck:   vcOpts.disabledProofCheck,
		ldpSuites:            vcOpts.ldpSuites,
		dataIntegrityOpts:    vcOpts.verifyDataIntegrity,
	}
}

func checkEmbeddedProof(docBytes []byte, opts *embeddedProofCheckOpts) error {
	if opts.disabledProofCheck {
		return nil
	}

	var jsonldDoc map[string]interface{}

	if err := json.Unmarshal(docBytes, &jsonldDoc); err != nil {
		return fmt.Errorf("embeded proof is not JSON: %w", err)
	}

	delete(jsonldDoc, "jwt")

	proofElement, ok := jsonldDoc["proof"]
	if !ok || proofElement == nil {
		return nil
	}

	proofs, err := getProofs(proofElement)
	if err != nil {
		return fmt.Errorf("check embedded proof: %w", err)
	}

	if len(opts.externalContext) > 0 {
		jsonldDoc["@context"] = jsonld.AppendExternalContexts(jsonldDoc["@context"], opts.externalContext...)
	}

	if len(proofs) > 0 {
		typeStr, ok := proofs[0]["type"]
		if ok && typeStr == models.DataIntegrityProof {
			docBytes, err := json.Marshal(jsonldDoc)
			if err != nil {
				return err
			}

			return checkDataIntegrityProof(docBytes, opts.dataIntegrityOpts)
		}
	}

	ldpSuites, err := getSuites(proofs, opts)
	if err != nil {
		return err
	}

	if opts.publicKeyFetcher == nil {
		return errors.New("public key fetcher is not defined")
	}

	err = checkLinkedDataProof(jsonldDoc, ldpSuites, opts.publicKeyFetcher, &opts.jsonldCredentialOpts)
	if err != nil {
		return fmt.Errorf("embedded proof check failed: %w", err)
	}

	return nil
}

func getProofs(proofElement interface{}) ([]map[string]interface{}, error) {
	switch p := proofElement.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{p}, nil

	case []interface{}:
		proofs := make([]map[string]interface{}, len(p))
		for i := range p {
			proofMap, ok := p[i].(map[string]interface{})
			if !ok {
				return nil, errors.New("invalid proof type")
			}

			proofs[i] = proofMap
		}
	}

	return nil, errors.New("invalid proof element")
}

func getSuites(proofs []map[string]interface{}, opts *embeddedProofCheckOpts) ([]sigapi.SignatureSuite, error) {
	return nil, errors.New("not implemented")
}
