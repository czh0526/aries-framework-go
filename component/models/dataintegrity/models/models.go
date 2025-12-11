package models

import (
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"time"
)

const (
	DataIntegrityProof = "DataIntegrityProof"
)

type Proof struct {
	ID                 string `json:"id,omitempty"`
	Type               string `json:"type"`
	CryptoSuite        string `json:"cryptosuite,omitempty"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
	Created            string `json:"created,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Challenge          string `json:"challenge,omitempty"`
	ProofValue         string `json:"proofValue"`
	PreviousProof      string `json:"previousProof,omitempty"`
}

type ProofOptions struct {
	Purpose              string
	VerificationMethodID string
	VerificationMethod   *didmodel.VerificationMethod
	ProofType            string
	SuiteType            string
	Domain               string
	Challenge            string
	Created              time.Time
	MaxAge               int64
	CustomFields         map[string]interface{}
}
