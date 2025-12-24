package holder

import (
	"crypto/ed25519"
	"crypto/rand"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/issuer"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	testIssuer = "https://example.com"
)

func TestParse(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := modeljwt.NewEd25519Signer(privKey)
	claims := map[string]interface{}{
		"given_name": "Albert",
	}

	token, err := issuer.New(testIssuer, claims, nil, signer)
	require.NoError(t, err)

	combinedFormatForIssuance, err := token.Serialize(false)
	require.NoError(t, err)

	verifier, err := modeljwt.NewEd25519Verifier(pubKey)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		claims, err := Parse(combinedFormatForIssuance, WithSignatureVerifier(verifier))
		require.NoError(t, err)
		require.Equal(t, 1, len(claims))
		require.Equal(t, "given_name", claims[0].Name)
		require.Equal(t, "Albert", claims[0].Value)
	})

	t.Run("success - default is no signature verifier", func(t *testing.T) {
		claims, err := Parse(combinedFormatForIssuance)
		require.NoError(t, err)
		require.Equal(t, 1, len(claims))
		require.Equal(t, "given_name", claims[0].Name)
		require.Equal(t, "Albert", claims[0].Value)
	})
}
