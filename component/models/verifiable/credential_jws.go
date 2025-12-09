package verifiable

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
)

func (jcc *JWTCredClaims) MarshalJWS(signatureAlg JWSAlgorithm, signer Signer, keyID string) (string, error) {
	return marshalJWS(jcc, signatureAlg, signer, keyID)
}

func unmarshalJWSClaims(
	rawJwt string,
	checkProof bool,
	fetcher didsignjwt.PublicKeyFetcher) (jose.Headers, *JWTCredClaims, error) {
	var claims JWTCredClaims

	joseHeaders, err := unmarshalJWS(rawJwt, checkProof, fetcher, &claims)
	if err != nil {
		return nil, nil, err
	}

	return joseHeaders, &claims, err
}

func decodeCredJWS(rawJwt string, checkProof bool, fetcher didsignjwt.PublicKeyFetcher) (jose.Headers, []byte, error) {
	return decodeCredJWT(rawJwt, func(vcJWTBytes string) (jose.Headers, *JWTCredClaims, error) {
		return unmarshalJWSClaims(rawJwt, checkProof, fetcher)
	})
}
