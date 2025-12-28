package verifiable

import (
	"encoding/json"
	verifiablemodel "github.com/czh0526/aries-framework-go/component/models/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	"time"
)

type Credential struct {
	VerifiableCredential string `json:"verifiableCredential,omitempty"`
}

type CredentialExt struct {
	Credential
	Name string `json:"name,omitempty"`
}

type IDArg struct {
	ID string `json:"id"`
}

type NameArg struct {
	Name string `json:"name"`
}

type RecordResult struct {
	// Result
	Result []*verifiable.Record `json:"result,omitempty"`
}

type SignCredentialRequest struct {
	Credential json.RawMessage `json:"credential,omitempty"`
	DID        string          `json:"did,omitempty"`
	*ProofOptions
}

type SignCredentialResponse struct {
	VerifiableCredential json.RawMessage `json:"verifiableCredential,omitempty"`
}

type ProofOptions struct {
	KID                     string                                   `json:"kid,omitempty"`
	VerificationMethod      string                                   `json:"verificationMethod,omitempty"`
	SignatureRepresentation *verifiablemodel.SignatureRepresentation `json:"signatureRepresentation,omitempty"`
	Created                 *time.Time                               `json:"created,omitempty"`
	Domain                  string                                   `json:"domain,omitempty"`
	Challenge               string                                   `json:"challenge,omitempty"`
	SignatureType           string                                   `json:"signatureType,omitempty"`
	proofPurpose            string
}
