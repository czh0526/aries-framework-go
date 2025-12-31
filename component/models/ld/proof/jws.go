package proof

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	"strings"
)

const (
	securityContext        = "https://w3id.org/security/v2"
	securityContextJWK2020 = "https://w3id.org/security/jws/v1"
)

const (
	jwtPartsNumber   = 3
	jwtHeaderPart    = 0
	jwtSignaturePart = 2
)

func CreateDetachedJWTHeader(alg string) string {
	jwtHeaderMap := map[string]interface{}{
		"alg":  alg,
		"b64":  false,
		"crit": []string{"b64"},
	}

	jwtHeaderBytes, err := json.Marshal(jwtHeaderMap)
	if err != nil {
		panic(err)
	}

	return base64.RawURLEncoding.EncodeToString(jwtHeaderBytes)
}

func getJWTHeader(jwt string) (string, error) {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != jwtPartsNumber {
		return "", errors.New("invalid JWT")
	}
	return jwtParts[jwtHeaderPart], nil
}

func createVerifyJWS(suite signatureSuite, jsonldDoc map[string]interface{},
	p *Proof, opts ...ldprocessormodel.Opts) ([]byte, error) {
	proofOptions := p.JSONLdObject()

	canonicalProofOptions, err := prepareJWSProof(suite, proofOptions, opts...)
	if err != nil {
		return nil, err
	}

	proofOptionsDigest := suite.GetDigest(canonicalProofOptions)

	canonicalDoc, err := prepareDocumentForJWS(suite, jsonldDoc, opts...)
	if err != nil {
		return nil, err
	}

	docDigest := suite.GetDigest(canonicalDoc)

	verifyData := append(proofOptionsDigest, docDigest...)

	jwtHeader, err := getJWTHeader(p.JWS)
	if err != nil {
		return nil, err
	}

	return append([]byte(jwtHeader+"."), verifyData...), nil
}

func prepareJWSProof(suite signatureSuite, proofOptions map[string]interface{},
	opts ...ldprocessormodel.Opts) ([]byte, error) {
	proofOptions[jsonldContext] = []interface{}{
		securityContext,
		securityContextJWK2020,
	}
	proofOptionsCopy := make(map[string]interface{}, len(proofOptions))

	for key, value := range proofOptions {
		proofOptionsCopy[key] = value
	}

	delete(proofOptionsCopy, jsonldJWS)
	delete(proofOptionsCopy, jsonldProofPurpose)

	return suite.GetCanonicalDocument(proofOptionsCopy, opts...)
}

func prepareDocumentForJWS(suite signatureSuite, jsonldObject map[string]interface{},
	opts ...ldprocessormodel.Opts) ([]byte, error) {
	doc := GetCopyWithoutProof(jsonldObject)

	if suite.CompactProof() {
		docCompacted, err := getCompactedWithSecuritySchema(doc, opts...)
		if err != nil {
			return nil, err
		}

		doc = docCompacted
	}

	return suite.GetCanonicalDocument(doc, opts...)
}

func getCompactedWithSecuritySchema(docMap map[string]interface{},
	opts ...ldprocessormodel.Opts) (map[string]interface{}, error) {
	contextMap := map[string]interface{}{
		"@context": securityContext,
	}

	return ldprocessormodel.Default().Compact(docMap, contextMap, opts...)
}
