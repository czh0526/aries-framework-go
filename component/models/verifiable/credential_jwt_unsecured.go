package verifiable

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
)

func (jcc *JWTCredClaims) MarshalUnsecuredJWT() (string, error) {
	return marshalUnsecuredJWT(nil, jcc)
}

func unmarshalUnsecuredJWTClaims(rawJWT string) (jose.Headers, *JWTCredClaims, error) {
	var claims JWTCredClaims

	hoseHeaders, err := unmarshalUnsecuredJWT(rawJWT, &claims)
	if err != nil {
		return nil, nil, fmt.Errorf("parse VC in JWT Unsecured form: %w", err)
	}

	return hoseHeaders, &claims, nil
}

func decodeCredJWTUnsecured(rawJwt string) ([]byte, error) {
	_, vcBytes, err := decodeCredJWT(rawJwt, unmarshalUnsecuredJWTClaims)

	return vcBytes, err
}
