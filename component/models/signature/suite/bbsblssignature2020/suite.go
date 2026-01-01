package bbsblssignature2020

import (
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	"github.com/czh0526/aries-framework-go/component/models/signature/suite"
)

const (
	SignatureType = "BbsBlsSignature2020"
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

func (s Suite) GetCanonicalDocument(doc map[string]interface{}, opts ...ldprocessormodel.Opts) ([]byte, error) {
	return s.jsonldProcessor.GetCanonicalDocument(doc, opts...)
}

func (s Suite) GetDigest(doc []byte) []byte {
	return doc
}

func (s Suite) Accept(t string) bool {
	return t == SignatureType
}
