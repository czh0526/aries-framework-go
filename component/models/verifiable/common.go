package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"strings"
)

type JWSAlgorithm int

const (
	RS256 JWSAlgorithm = iota
	PS256
	EdDSA

	ECDSASecp256k1

	ECDSASecp256r1
	ECDSASecp384r1
	ECDSASecp521r1
)

func KeyTypeToJWSAlgo(keyType spikms.KeyType) (JWSAlgorithm, error) {
	switch keyType {
	case spikms.ECDSAP256TypeDER, spikms.ECDSAP256TypeIEEEP1363:
		return ECDSASecp256r1, nil
	case spikms.ECDSAP384TypeDER, spikms.ECDSAP384TypeIEEEP1363:
		return ECDSASecp384r1, nil
	case spikms.ECDSAP521TypeDER, spikms.ECDSAP521TypeIEEEP1363:
		return ECDSASecp521r1, nil
	case spikms.ED25519Type:
		return EdDSA, nil
	case spikms.ECDSASecp256k1TypeDER, spikms.ECDSASecp256k1TypeIEEEP1363:
		return ECDSASecp256k1, nil
	case spikms.RSARS256Type:
		return RS256, nil
	case spikms.RSAPS256Type:
		return PS256, nil
	default:
		return 0, errors.New("unsupported key type")
	}
}

func (ja JWSAlgorithm) Name() (string, error) {
	switch ja {
	case RS256:
		return "RS256", nil
	case PS256:
		return "PS256", nil
	case EdDSA:
		return "EdDSA", nil
	case ECDSASecp256k1:
		return "ES256K", nil
	case ECDSASecp256r1:
		return "ES256", nil
	case ECDSASecp384r1:
		return "ES384", nil
	case ECDSASecp521r1:
		return "ES521", nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %v", ja)
	}
}

type CustomFields map[string]interface{}

type TypedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

func newTypedID(v interface{}) (TypedID, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return TypedID{}, nil
	}

	var tid TypedID
	err = json.Unmarshal(bytes, &tid)

	return tid, err
}

func decodeType(t interface{}) ([]string, error) {
	switch rType := t.(type) {
	case string:
		return []string{rType}, nil
	case []interface{}:
		types, err := stringSlice(rType)
		if err != nil {
			return nil, fmt.Errorf("vc types: %w", err)
		}
		return types, nil
	default:
		return nil, errors.New("credential type of unknown structure")
	}
}

type Proof map[string]interface{}

func stringSlice(values []interface{}) ([]string, error) {
	s := make([]string, len(values))

	for i := range values {
		t, valid := values[i].(string)
		if !valid {
			return nil, errors.New("array element is not a string")
		}

		s[i] = t
	}

	return s, nil
}

func parseProof(proofBytes json.RawMessage) ([]Proof, error) {
	if len(proofBytes) == 0 {
		return nil, nil
	}

	var singleProof Proof
	err := json.Unmarshal(proofBytes, &singleProof)
	if err == nil {
		return []Proof{singleProof}, nil
	}

	var composedProof []Proof
	err = json.Unmarshal(proofBytes, &composedProof)
	if err == nil {
		return composedProof, nil
	}

	return nil, err
}

func decodeContext(c interface{}) ([]string, []interface{}, error) {
	switch rContext := c.(type) {
	case string:
		return []string{rContext}, nil, nil

	case []interface{}:
		s := make([]string, 0)

		for i := range rContext {
			c, valid := rContext[i].(string)
			if !valid {
				return s, rContext[i:], nil
			}

			s = append(s, c)
		}
		return s, nil, nil

	default:
		return nil, nil, errors.New("credential context of unknown type")
	}
}

func safeStringValue(v interface{}) string {
	if v == nil {
		return ""
	}

	return v.(string)
}

type VDRKeyResolver struct {
	vdr didResolver
}

func (v *VDRKeyResolver) PublicKeyFetcher() didsignjwt.PublicKeyFetcher {
	return v.resolvePublicKey
}

func (v *VDRKeyResolver) resolvePublicKey(issuerDID, keyID string) (*sigapi.PublicKey, error) {
	docResolution, err := v.vdr.Resolve(issuerDID)
	if err != nil {
		return nil, err
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if strings.Contains(verification.VerificationMethod.ID, keyID) &&
				verification.Relationship != didmodel.KeyAgreement {
				return &sigapi.PublicKey{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", keyID, issuerDID)
}

type didResolver interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (didmodel.DocResolution, error)
}

func NewVDRKeyResolver(vdr didResolver) *VDRKeyResolver {
	return &VDRKeyResolver{
		vdr: vdr,
	}
}
