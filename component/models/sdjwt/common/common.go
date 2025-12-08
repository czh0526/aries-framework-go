package common

import "strings"

type SDJWTVersion int

const (
	CombinedFormatSeparator = "~"
)

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

type CombinedFormatForIssuance struct {
	SDJWT       string
	Disclosures []string
}

type CombineFormatForPresentation struct {
	SDJWT              string
	Disclosures        []string
	HolderVerification string
}

func ParseCombinedFormatForIssuance(combinedFormatForIssuance string) *CombinedFormatForIssuance {
	parts := strings.Split(combinedFormatForIssuance, CombinedFormatSeparator)

	var disclosures []string
	if len(parts) > 1 {
		disclosures = parts[1:]
	}

	sdJWT := parts[0]

	return &CombinedFormatForIssuance{
		SDJWT:       sdJWT,
		Disclosures: disclosures,
	}
}

func ParseCombinedFormatForPresentation(combineFormatForPresentation string) *CombineFormatForPresentation {
	parts := strings.Split(combineFormatForPresentation, CombinedFormatSeparator)

	var disclosures []string
	if len(parts) > 2 {
		disclosures = parts[1 : len(parts)-1]
	}

	var holderBinding string
	if len(parts) > 1 {
		holderBinding = parts[len(parts)-1]
	}

	sdJWT := parts[0]

	return &CombineFormatForPresentation{
		SDJWT:              sdJWT,
		Disclosures:        disclosures,
		HolderVerification: holderBinding,
	}
}
