package common

type SDJWTVersion int

const (
	SDJWTVersionDefault = SDJWTVersionV2
	SDJWTVersionV2      = SDJWTVersion(2)
	SDJWTVersionV5      = SDJWTVersion(5)
)

type DisclosureClaimType int

const (
	DisclosureClaimTypeUnknown      = DisclosureClaimType(0)
	DisclosureClaimTypeArrayElement = DisclosureClaimType(2)
	DisclosureClaimTypeObject       = DisclosureClaimType(3)
	DisclosureClaimTypePlainText    = DisclosureClaimType(4)
)

type DisclosureClaim struct {
	Digest        string
	Disclosure    string
	Salt          string
	Elements      int
	Type          DisclosureClaimType
	Version       SDJWTVersion
	Name          string
	Value         interface{}
	IsValueParsed bool
}
