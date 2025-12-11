package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/jwt"
)

func unmarshalUnsecuredJWT(rawJWT string, claims interface{}) (jose.Headers, error) {
	token, _, err := jwt.Parse(rawJWT, jwt.WithSignatureVerifier(jwt.UnsecuredJWTVerifier()))
	if err != nil {
		return nil, fmt.Errorf("unmarshal unsecured JWT: %w", err)
	}

	return token.Headers, token.DecodeClaims(claims)
}

func marshalUnsecuredJWT(headers jose.Headers, claims interface{}) (string, error) {
	token, err := jwt.NewUnsecured(claims, headers)
	if err != nil {
		return "", fmt.Errorf("marshal unsecured JWT: %w", err)
	}

	return token.Serialize(false)
}
