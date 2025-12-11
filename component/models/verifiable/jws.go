package verifiable

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

type JwtSigner struct {
	signer  Signer
	headers map[string]interface{}
}

func (s JwtSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

func (s JwtSigner) Headers() jose.Headers {
	return s.headers
}

func GetJWTSigner(signer Signer, algorithm string) *JwtSigner {
	headers := map[string]interface{}{
		jose.HeaderAlgorithm: algorithm,
	}

	return &JwtSigner{
		signer:  signer,
		headers: headers,
	}
}

type noVerifier struct{}

func (n noVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

var _ jose.SignatureVerifier = (*noVerifier)(nil)

func marshalJWS(jwtClaims interface{}, signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	algName, err := signatureAlg.Name()
	if err != nil {
		return "", err
	}

	headers := map[string]interface{}{
		jose.HeaderKeyID: keyID,
	}

	token, err := jwt.NewSigned(jwtClaims, headers, GetJWTSigner(signer, algName))
	if err != nil {
		return "", err
	}

	return token.Serialize(false)
}

func unmarshalJWS(rawJwt string, checkProof bool, fetcher didsignjwt.PublicKeyFetcher, claims interface{}) (jose.Headers, error) {
	var verifier jose.SignatureVerifier

	if checkProof {
		verifier = jwt.NewVerifier(jwt.KeyResolveFunc(fetcher))
	} else {
		verifier = &noVerifier{}
	}

	jsonWebToken, claimsRaw, err := jwt.Parse(rawJwt,
		jwt.WithSignatureVerifier(verifier),
		jwt.WithIgnoreClaimsMapDecoding(true))
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	err = json.Unmarshal(claimsRaw, claims)
	if err != nil {
		return nil, err
	}

	return jsonWebToken.Headers, nil
}
