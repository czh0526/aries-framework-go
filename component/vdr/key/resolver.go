package key

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"regexp"
)

func (v *VDR) Read(didKey string, _ ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
	parsed, err := didmodel.Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to parse DID document: %w", err)
	}

	if parsed.Method != "key" {
		return nil, fmt.Errorf("vdr Read: invalid did:key method: %s", parsed.Method)
	}

	if !isValidMethodID(parsed.MethodSpecificID) {
		return nil, fmt.Errorf("vdr Read: invalid did:key method ID: %s", parsed.Method)
	}

	pubKeyBytes, code, err := fingerprint.PubKeyFromFingerprint(parsed.MethodSpecificID)
	if err != nil {
		return nil, fmt.Errorf("vdr Read: failed to get public key from fingerPrint: %w", err)
	}

	didDoc, err := createDIDDocFromPubKey(parsed.MethodSpecificID, code, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("create DID document from public key failed: %w", err)
	}

	return &didmodel.DocResolution{
		Context:     []string{schemaResV1},
		DIDDocument: didDoc,
	}, nil
}

func isValidMethodID(id string) bool {
	r := regexp.MustCompile(`(z)([1-9a-km-zA-HJ-NP-Z]{46})`)
	return r.MatchString(id)
}
