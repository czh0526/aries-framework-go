package did

import (
	"encoding/base64"
	"errors"
	sigproof "github.com/czh0526/aries-framework-go/component/models/ld/proof"
	"strings"
	"time"
)

type Proof struct {
	Type         string
	Created      *time.Time
	Creator      string
	ProofValue   []byte
	Domain       string
	Nonce        []byte
	ProofPurpose string
	relativeURL  bool
}

func populateProofs(context, didID, baseURI string, rawProofs []interface{}) ([]Proof, error) {
	proofs := make([]Proof, 0, len(rawProofs))

	for _, rawProof := range rawProofs {
		emap, ok := rawProof.(map[string]interface{})
		if !ok {
			return nil, errors.New("rawProofs is not map[string]interface{}")
		}

		created := stringEntry(emap[jsonldCreated])
		timeValue, err := time.Parse(time.RFC3339, created)
		if err != nil {
			return nil, err
		}

		proofKey := jsonldProofValue
		if context == contextV011 {
			proofKey = jsonldSignatureValue
		}

		proofValue, err := sigproof.DecodeProofValue(
			stringEntry(emap[proofKey]),
			stringEntry(emap[jsonldType]))

		nonce, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[jsonldNonce]))
		if err != nil {
			return nil, err
		}

		creator := stringEntry(emap[jsonldCreator])

		isRelative := false

		if strings.HasPrefix(creator, "#") {
			creator = resolveRelativeDIDURL(didID, baseURI, creator)
			isRelative = true
		}

		proof := Proof{
			Type:         stringEntry(emap[jsonldType]),
			Created:      &timeValue,
			Creator:      creator,
			ProofValue:   proofValue,
			ProofPurpose: stringEntry(emap[jsonldProofPurpose]),
			Domain:       stringEntry(emap[jsonldDomain]),
			Nonce:        nonce,
			relativeURL:  isRelative,
		}

		proofs = append(proofs, proof)
	}

	return proofs, nil
}

func populateRawProofs(context, baseURI, didID string, proofs []Proof) []interface{} {
	rawProofs := make([]interface{}, 0, len(proofs))

	k := jsonldProofValue
	if context == contextV011 {
		k = jsonldSignatureValue
	}

	for _, p := range proofs {
		creator := p.Creator
		if p.relativeURL {
			creator = makeRelativeDIDURL(p.Creator, baseURI, didID)
		}

		rawProofs = append(rawProofs, map[string]interface{}{
			jsonldType:         p.Type,
			jsonldCreated:      p.Created,
			jsonldCreator:      creator,
			k:                  sigproof.EncodeProofValue(p.ProofValue, p.Type),
			jsonldDomain:       p.Domain,
			jsonldNonce:        base64.RawURLEncoding.EncodeToString(p.Nonce),
			jsonldProofPurpose: p.ProofPurpose,
		})
	}

	return rawProofs
}
