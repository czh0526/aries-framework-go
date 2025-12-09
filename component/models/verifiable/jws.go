package verifiable

import (
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
		verifier = jwt.NewVerifier(jwt.KeyResolverFunc(fetcher))
	}
}
