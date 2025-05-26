package jwkkid

import (
	"encoding/base64"
	"errors"
	"fmt"
)

func createBLS12381G2KID(keyBytes []byte) (string, error) {
	const (
		bls12381g2ThumbprintTemplate = `{"crv":"Bls12381g2","kty":"OKP","x":"%s"}`
		bls12381G2PublicKeyLen       = 96
	)

	lenKey := len(keyBytes)
	if lenKey > bls12381G2PublicKeyLen {
		return "", errors.New("invalid BBS + key")
	}

	pad := make([]byte, bls12381G2PublicKeyLen-lenKey)
	bbsRawKey := append(pad, keyBytes...)

	j := fmt.Sprintf(bls12381g2ThumbprintTemplate, base64.RawURLEncoding.EncodeToString(bbsRawKey))

	thumbprint := sha256Sum(j)

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
