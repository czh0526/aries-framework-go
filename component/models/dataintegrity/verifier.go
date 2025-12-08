package dataintegrity

type Verifier struct {
	suites   map[string]suite.Verifier
	resolver didResolver
}
