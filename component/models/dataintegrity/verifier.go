package dataintegrity

import "github.com/czh0526/aries-framework-go/component/models/dataintegrity/suite"

type Verifier struct {
	suites   map[string]suite.Verifier
	resolver didResolver
}
