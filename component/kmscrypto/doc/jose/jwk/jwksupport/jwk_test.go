package jwksupport

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDecodeJWK(t *testing.T) {

	t.Run("test Ed25519 JWK", func(t *testing.T) {
		jwkJson := []byte(`{
					"kty": "OKP",
					"use": "enc",
					"crv": "Ed25519",
					"kid": "sample@sample.id",
					"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
					"alg": "EdDSA"
				}`)

		var jwkKey jwk.JWK
		err := json.Unmarshal(jwkJson, &jwkKey)
		require.NoError(t, err)

		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		jwkBytes, err := json.Marshal(jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		jwkKey2, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotNil(t, jwkKey2)
		require.Equal(t, "Ed25519", jwkKey2.Crv)
		require.Equal(t, ed25519.PublicKeySize, len(jwkKey2.Key.(ed25519.PublicKey)))
		require.Equal(t, okpKty, jwkKey2.Kty)

	})

}
