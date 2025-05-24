package jwkkid

import (
	"encoding/json"
	"errors"
	"fmt"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/czh0526/aries-framework-go/component/kmcrypto/util/cryptoutil"
)

func CreateKID(keyBytes []byte, kt spikms.KeyType) (string, error) {
	if len(keyBytes) == 0 {
		return "", errors.New("createKID: empty key")
	}

	switch kt {
	case spikms.X25519ECDHKWType:
		x25519KID, err := createX25519KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %v", err)
		}

		return x25519KID, nil

	case spikms.BLS12381G2Type:
		bbsKID, err := createBLS12381G2KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %v", err)
		}

		return bbsKID, nil

	case spikms.ECDSASecp256k1TypeDER, spikms.ECDSASecp256k1TypeIEEEP1363:
		secp256k1KID, err := secp256k1Thumbprint(keyBytes, kt)
		if err != nil {
			return "", fmt.Errorf("createKID: %v", err)
		}

		return secp256k1KID, nil
	}

	j, err := BuildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to build jwk: %v", err)
	}

	tp, err := j.Th
}

func unmarshalECDHKey(keyBytes []byte) (*spicrypto.PublicKey, error) {
	compositeKey := &spicrypto.PublicKey{}

	err := json.Unmarshal(keyBytes, compositeKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalECDHKey: failed to unmarshal ECDH Key: %v", err)
	}

	return compositeKey, nil
}

func buildX25519JWK(keyBytes []byte) (string, error) {
	const x25519ThumbprintTemplate = `{"crv": "X25519", "kty": "OKP", "x": "%s"}`

	lenKey := len(keyBytes)
	if lenKey > cryptoutil.
}

func createX25519KID(marshalledKey []byte) (string, error) {
	compositeKey, err := unmarshalECDHKey(marshalledKey)
	if err != nil {
		return "", fmt.Errorf("createX25519KID: %v", err)
	}

	j, err := buildX25519JWK(compositeKey.X)
}
