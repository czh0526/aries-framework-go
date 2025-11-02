package verifiable

import (
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
)

type Issuer struct {
	ID           string       `json:"id,omitempty"`
	CustomFields CustomFields `json:"customFields,omitempty"`
}

type Evidence interface{}

type Credential struct {
	Context          []string
	CustomContext    []interface{}
	ID               string
	Types            []string
	Subject          interface{}
	Issuer           Issuer
	Issued           *timeutil.TimeWrapper
	Expired          *timeutil.TimeWrapper
	Proofs           []Proof
	Status           *TypedID
	Schemas          []TypedID
	Evidence         Evidence
	TermsOfUse       []TypedID
	RefreshService   []TypedID
	JWT              string
	SDJWTVersion     common.SDJWTVersion
	SDJWTHashAlg     string
	SDJWTDisclosures []*common.DisclosureClaim
	SDHolderBinding  string
	CustomFields     CustomFields
}
