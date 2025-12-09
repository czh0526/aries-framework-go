package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/go-jose/go-jose/v3/jwt"
	"time"
)

const (
	vcIssuanceDateField   = "issuanceDate"
	vcIDField             = "id"
	vcExpirationDataField = "expirationDate"
	vcIssuerField         = "issuer"
	vcIssuerIDField       = "id"
)

type JWTCredClaims struct {
	*jwt.Claims

	VC map[string]interface{} `json:"vc,omitempty"`
}

type JWTCredClaimsUnmarshaller func(vcJWTBytes string) (jose.Headers, *JWTCredClaims, error)

func decodeCredJWT(rawJWT string, unmarshaller JWTCredClaimsUnmarshaller) (jose.Headers, []byte, error) {
	joseHeaders, credClaims, err := unmarshaller(rawJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal VC JWT claims: %w", err)
	}

	credClaims.refineFromJWTClaims()

	vcData, err := json.Marshal(credClaims.VC)
	if err != nil {
		return nil, nil, errors.New("failed to marshal 'vc' claim of JWT")
	}

	return joseHeaders, vcData, nil
}

func (jcc *JWTCredClaims) refineFromJWTClaims() {
	vcMap := jcc.VC
	claims := jcc.Claims

	if iss := claims.Issuer; iss != "" {
		refineVCIssuerFromJWTClaims(vcMap, iss)
	}

	if nbf := claims.NotBefore; nbf != nil {
		nbfTime := nbf.Time().UTC()
		vcMap[vcIssuanceDateField] = nbfTime.Format(time.RFC3339)
	}

	if jti := claims.ID; jti != "" {
		vcMap[vcIDField] = jti
	}

	if iat := claims.IssuedAt; iat != nil {
		iatTime := iat.Time().UTC()
		vcMap[vcIssuanceDateField] = iatTime.Format(time.RFC3339)
	}

	if exp := claims.Expiry; exp != nil {
		expTime := exp.Time().UTC()
		vcMap[vcExpirationDataField] = expTime.Format(time.RFC3339)
	}
}

func refineVCIssuerFromJWTClaims(vcMap map[string]interface{}, iss string) {
	if _, exists := vcMap[vcIssuerField]; !exists {
		vcMap[vcIssuerField] = iss
		return
	}

	switch issuer := vcMap[vcIssuerField].(type) {
	case string:
		vcMap[vcIssuerField] = iss
	case map[string]interface{}:
		issuer[vcIssuerIDField] = iss
	}
}
