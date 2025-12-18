package verifiable

import (
	"encoding/json"
	"fmt"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
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

func (s JwtSigner) Headers() docjose.Headers {
	return s.headers
}

func GetJWTSigner(signer Signer, algorithm string) *JwtSigner {
	headers := map[string]interface{}{
		docjose.HeaderAlgorithm: algorithm,
	}

	return &JwtSigner{
		signer:  signer,
		headers: headers,
	}
}

type noVerifier struct{}

func (n noVerifier) Verify(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

var _ docjose.SignatureVerifier = (*noVerifier)(nil)

func marshalJWS(jwtClaims interface{}, signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	algName, err := signatureAlg.Name()
	if err != nil {
		return "", err
	}

	headers := map[string]interface{}{
		docjose.HeaderKeyID: keyID,
	}

	token, err := modeljwt.NewSigned(jwtClaims, headers, GetJWTSigner(signer, algName))
	if err != nil {
		return "", err
	}

	return token.Serialize(false)
}

func unmarshalJWS(rawJwt string, checkProof bool, fetcher didsignjwt.PublicKeyFetcher, claims interface{}) (docjose.Headers, error) {
	var verifier docjose.SignatureVerifier

	if checkProof {
		verifier = modeljwt.NewVerifier(modeljwt.KeyResolveFunc(fetcher))
	} else {
		verifier = &noVerifier{}
	}

	jsonWebToken, claimsRaw, err := modeljwt.Parse(rawJwt,
		modeljwt.WithSignatureVerifier(verifier),
		modeljwt.WithIgnoreClaimsMapDecoding(true))
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	err = json.Unmarshal(claimsRaw, claims)
	if err != nil {
		return nil, err
	}

	return jsonWebToken.Headers, nil
}
