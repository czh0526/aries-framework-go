package verifiable

import (
	"errors"
	"fmt"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
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

type Proof map[string]interface{}
