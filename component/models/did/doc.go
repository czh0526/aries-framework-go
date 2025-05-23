package did

import (
	"time"
)

type Context interface{}

type processingMeta struct {
	baseURI string
}

type Doc struct {
	Context              Context
	ID                   string
	AlsoKnownAs          []string
	VerificationMethod   []VerificationMethod
	Service              []Service
	Authentication       []Verification
	AssertMethod         []Verification
	CapabilityDelegation []Verification
	CapabilityInvocation []Verification
	KeyAgreement         []Verification
	Created              *time.Time
	Updated              *time.Time
	Proof                []Proof
	processingMeta       processingMeta
}

type DocResolution struct {
	Context          Context
	DIDDocument      *Doc
	DocumentMetadata *DocumentMetadata
}
