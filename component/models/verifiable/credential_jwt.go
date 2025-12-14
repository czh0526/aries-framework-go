package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
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
	*josejwt.Claims

	VC map[string]interface{} `json:"vc,omitempty"`
}

func newJWTCredClaims(vc *Credential, minimizeVC bool) (*JWTCredClaims, error) {
	subjectID, err := SubjectID(vc.Subject)
	if err != nil {
		return nil, fmt.Errorf("get VC subject id: %w", err)
	}

	jwtClaims := &josejwt.Claims{
		Issuer:    vc.Issuer.ID,
		NotBefore: josejwt.NewNumericDate(vc.Issued.Time),
		ID:        vc.ID,
		Subject:   subjectID,
	}

	if vc.Expired != nil {
		jwtClaims.Expiry = josejwt.NewNumericDate(vc.Expired.Time)
	}

	if vc.Issued != nil {
		jwtClaims.IssuedAt = josejwt.NewNumericDate(vc.Issued.Time)
	}

	var raw *rawCredential
	if minimizeVC {
		vcCopy := *vc
		vcCopy.Expired = nil
		vcCopy.Issuer.ID = ""
		vcCopy.Issued = nil
		vcCopy.ID = ""

		raw, err = vcCopy.raw()
	} else {
		raw, err = vc.raw()
	}

	if err != nil {
		return nil, err
	}

	raw.JWT = ""

	vcMap, err := jsonutil.MergeCustomFields(raw, raw.CustomFields)
	if err != nil {
		return nil, err
	}

	credClaims := &JWTCredClaims{
		Claims: jwtClaims,
		VC:     vcMap,
	}

	return credClaims, nil
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

func SubjectID(subject interface{}) (string, error) {
	switch subject := subject.(type) {
	case []Subject:
		if len(subject) == 0 {
			return "", errors.New("no subject is defined")
		}
		if len(subject) > 1 {
			return "", errors.New("mor than one subject is defined")
		}

		return subject[0].ID, nil

	case Subject:
		return subject.ID, nil

	case map[string]interface{}:
		return subjectIDFromMap(subject)

	case []map[string]interface{}:
		if len(subject) == 0 {
			return "", errors.New("no subject is defined")
		}
		if len(subject) > 1 {
			return "", errors.New("mor than one subject is defined")
		}

		return subjectIDFromMap(subject[0])

	case string:
		return subject, nil
	default:
		sMap, err := jsonutil.ToMap(subject)
		if err != nil {
			return "", errors.New("subject of unknown structure")
		}

		return SubjectID(sMap)
	}
}

func subjectIDFromMap(subject map[string]interface{}) (string, error) {
	subjectWithID, defined := subject["id"]
	if !defined {
		return "", errors.New("subject id is not defined")
	}

	subjectID, isString := subjectWithID.(string)
	if !isString {
		return "", errors.New("subject id is not a string")
	}

	return subjectID, nil
}
