package did

type VerificationRelationship int

const (
	VerificationRelationshipGeneral VerificationRelationship = iota
	Authentication
	AssertionMethod
	CapabilityDelegation
	CapabilityInvocation
	KeyAgreement
)

type Verification struct {
	VerificationMethod VerificationMethod
	Relationship       VerificationRelationship
	Embedded           bool
}
