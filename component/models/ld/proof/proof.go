package proof

import (
	"encoding/base64"
	"errors"
	"github.com/multiformats/go-multibase"

	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
)

const (
	jsonldType               = "type"
	jsonldCreator            = "creator"
	jsonldCreated            = "created"
	jsonldDomain             = "domain"
	jsonldNonce              = "nonce"
	jsonldProofValue         = "proofValue"
	jsonldProofPurpose       = "proofPurpose"
	jsonldJWS                = "jws"
	jsonldVerificationMethod = "verificationMethod"
	jsonldChallenge          = "challenge"
	jsonldCapabilityChain    = "capabilityChain"

	ed25519Signature2020 = "Ed25519Signature2020"
)

type Proof struct {
	Type                    string
	Created                 *timeutil.TimeWrapper
	Creator                 string
	VerificationMethod      string
	ProofValue              []byte
	JWS                     string
	ProofPurpose            string
	Domain                  string
	Nonce                   []byte
	Challenge               string
	SignatureRepresentation SignatureRepresentation
	CapabilityChain         []interface{}
}

func (p *Proof) JSONLdObject() map[string]interface{} {
	emap := make(map[string]interface{})
	emap[jsonldType] = p.Type

	if p.Creator != "" {
		emap[jsonldCreator] = p.Creator
	}

	if p.VerificationMethod != "" {
		emap[jsonldVerificationMethod] = p.VerificationMethod
	}

	if p.Created != nil {
		emap[jsonldCreated] = p.Created.FormatToString()
	}

	if len(p.ProofValue) > 0 {
		emap[jsonldProofValue] = EncodeProofValue(p.ProofValue, p.Type)
	}

	if len(p.JWS) > 0 {
		emap[jsonldJWS] = p.JWS
	}

	if p.Domain != "" {
		emap[jsonldDomain] = p.Domain
	}

	if len(p.Nonce) > 0 {
		emap[jsonldNonce] = base64.RawURLEncoding.EncodeToString(p.Nonce)
	}

	if p.ProofPurpose != "" {
		emap[jsonldProofPurpose] = p.ProofPurpose
	}

	if p.Challenge != "" {
		emap[jsonldChallenge] = p.Challenge
	}

	if p.CapabilityChain != nil {
		emap[jsonldCapabilityChain] = p.CapabilityChain
	}

	return emap
}

func EncodeProofValue(proofValue []byte, proofType string) string {
	if proofType == ed25519Signature2020 {
		encoded, _ := multibase.Encode(multibase.Base58BTC, proofValue)
		return encoded
	}

	return base64.RawURLEncoding.EncodeToString(proofValue)
}

func DecodeProofValue(s, proofType string) ([]byte, error) {
	if proofType == ed25519Signature2020 {
		_, value, err := multibase.Decode(s)
		if err == nil {
			return value, nil
		}

		return nil, errors.New("unsupported encoding")
	}

	return decodeBase64(s)
}

func decodeBase64(s string) ([]byte, error) {
	allEncodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.StdEncoding,
		base64.RawStdEncoding,
	}

	for _, encoding := range allEncodings {
		value, err := encoding.DecodeString(s)
		if err == nil {
			return value, nil
		}
	}

	return nil, errors.New("unsupported encoding")
}
