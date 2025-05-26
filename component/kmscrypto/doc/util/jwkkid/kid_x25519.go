package jwkkid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
)

func createX25519KID(marshalledKey []byte) (string, error) {
	compositeKey, err := unmarshalECDHKey(marshalledKey)
	if err != nil {
		return "", fmt.Errorf("createX25519KID: %v", err)
	}

	j, err := buildX25519JWK(compositeKey.X)
	if err != nil {
		return "", fmt.Errorf("createX25519KID: %v", err)
	}

	thumbprint := sha256Sum(j)

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func buildX25519JWK(keyBytes []byte) (string, error) {
	const x25519ThumbprintTemplate = `{"crv": "X25519", "kty": "OKP", "x": "%s"}`

	lenKey := len(keyBytes)
	if lenKey > cryptoutil.Curve25519KeySize {
		return "", errors.New("buildX25519JWK: invalid ECDH X25519 key")
	}

	pad := make([]byte, cryptoutil.Curve25519KeySize-lenKey)
	x25519RawKey := append(pad, keyBytes...)

	j := fmt.Sprintf(x25519ThumbprintTemplate, base64.RawURLEncoding.EncodeToString(x25519RawKey))

	return j, nil
}

func unmarshalECDHKey(keyBytes []byte) (*spicrypto.PublicKey, error) {
	compositeKey := &spicrypto.PublicKey{}

	err := json.Unmarshal(keyBytes, compositeKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalECDHKey: failed to unmarshal ECDH Key: %v", err)
	}

	return compositeKey, nil
}
