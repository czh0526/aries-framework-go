package ed25519signature2018

import (
	"crypto/sha256"
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	"github.com/czh0526/aries-framework-go/component/models/signature/suite"
)

const (
	SignatureType = "Ed25519Signature2018"
	rdfDataSetAlg = "URDNA2015"
)

type Suite struct {
	suite.SignatureSuite
	jsonldProcessor *ldprocessormodel.Processor
}

func New(opts ...suite.Opt) *Suite {
	s := &Suite{
		jsonldProcessor: ldprocessormodel.NewProcessor(rdfDataSetAlg),
	}

	suite.InitSuiteOptions(&s.SignatureSuite, opts...)

	return s
}

func (s *Suite) GetCanonicalDocument(doc map[string]interface{}, opts ...ldprocessormodel.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

func (s *Suite) GetDigest(doc []byte) []byte {
	digest := sha256.Sum256(doc)
	return digest[:]
}

func (s *Suite) Accept(t string) bool {
	return t == SignatureType
}
