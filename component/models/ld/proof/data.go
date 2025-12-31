package proof

import (
	"errors"
	"fmt"
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
)

const jsonldContext = "@context"

type signatureSuite interface {
	GetCanonicalDocument(doc map[string]interface{}, opts ...ldprocessormodel.Opts) ([]byte, error)

	GetDigest(doc []byte) []byte

	CompactProof() bool
}

type SignatureRepresentation int

const (
	SignatureProofValue SignatureRepresentation = iota
	SignatureJWS
)

func CreateVerifyData(suite signatureSuite, jsonldDoc map[string]interface{}, proof *Proof,
	opts ...ldprocessormodel.Opts) ([]byte, error) {
	switch proof.SignatureRepresentation {
	case SignatureProofValue:
		return CreateVerifyHash(suite, jsonldDoc, proof.JSONLdObject(), opts...)
	case SignatureJWS:
		return createVerifyJWS(suite, jsonldDoc, proof, opts...)
	}

	return nil, fmt.Errorf("unsupported signature representation: %v", proof.SignatureRepresentation)
}

func CreateVerifyHash(suite signatureSuite, jsonldDoc, proofOptions map[string]interface{},
	opts ...ldprocessormodel.Opts) ([]byte, error) {
	_, ok := proofOptions[jsonldContext]
	if !ok {
		proofOptions[jsonldContext] = jsonldDoc[jsonldContext]
	}

	canonicalProofOptions, err := prepareCanonicalProofOptions(suite, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := suite.GetDigest(canonicalProofOptions)

	canonicalDoc, err := suite.GetCanonicalDocument(jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := suite.GetDigest(canonicalDoc)

	return append(proofOptionsDigest, docDigest...), nil
}

func prepareCanonicalProofOptions(suite signatureSuite, proofOptions map[string]interface{},
	opts ...ldprocessormodel.Opts) ([]byte, error) {
	value, ok := proofOptions[jsonldCreated]
	if !ok || value == nil {
		return nil, errors.New("created is missing`")
	}

	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))
	for k, v := range proofOptions {
		if excludedKeyFromString(k) == 0 {
			proofOptionsCopy[k] = v
		}
	}

	if suite.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(proofOptionsCopy, opts...)
		if err != nil {
			return nil, err
		}

		proofOptionsCopy = docCompacted
	}

	return suite.GetCanonicalDocument(proofOptionsCopy, opts...)
}

type excludedKey uint

const (
	proofID excludedKey = iota + 1
	proofValue
	jws
	nonce
)

var (
	excludedKeysStr = [...]string{"id", "proofValue", "jws", "nonce"}
	excludedKeys    = [...]excludedKey{proofID, proofValue, jws, nonce}
)

func (ek excludedKey) String() string {
	return excludedKeysStr[ek]
}

func excludedKeyFromString(s string) excludedKey {
	for _, ek := range excludedKeys {
		if s == ek.String() {
			return ek
		}
	}

	return 0
}
