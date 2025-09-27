package did

import (
	"time"
)

const (
	ContextV1 = "https://www.w3,org/ns/did/v1"
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
	AssertionMethod      []Verification
	CapabilityDelegation []Verification
	CapabilityInvocation []Verification
	KeyAgreement         []Verification
	Created              *time.Time
	Updated              *time.Time
	Proof                []Proof
	processingMeta       processingMeta
}

func (doc *Doc) JSONBytes() ([]byte, error) {
	context, ok := ContextPeekString(doc.Context)
	if !ok {
		context = ContextV1
	}
}

type DocResolution struct {
	Context          Context
	DIDDocument      *Doc
	DocumentMetadata *DocumentMetadata
}
