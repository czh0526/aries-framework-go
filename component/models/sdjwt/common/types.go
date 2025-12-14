package common

type recursiveData struct {
	disclosures          map[string]*DisclosureClaim
	nestedSD             []string
	cleanupDigestsClaims bool
}
