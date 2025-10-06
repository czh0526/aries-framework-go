package proof

import (
	"encoding/base64"
	"errors"
	"github.com/multiformats/go-multibase"
)

const (
	ed25519Signature2020 = "Ed25519Signature2020"
)

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
