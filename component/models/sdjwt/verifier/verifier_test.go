package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	afjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/issuer"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"testing"
	"time"

	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer = "https://example.com/issuer"

	year = 365 * 24 * time.Hour
)

func TestParse(t *testing.T) {
	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)

	signer := modeljwt.NewEd25519Signer(privKey)
	selectiveClaims := map[string]interface{}{
		"given_name": "Albert",
	}

	now := time.Now()

	var timeOpts []issuer.NewOpt
	timeOpts = append(timeOpts,
		issuer.WithNotBefore(josejwt.NewNumericDate(now)),
		issuer.WithIssuedAt(josejwt.NewNumericDate(now)),
		issuer.WithExpiry(josejwt.NewNumericDate(now.Add(year))),
		issuer.WithSDJWTVersion(common.SDJWTVersionV2),
	)

	headers := afjose.Headers{
		afjose.HeaderType: "JWT",
	}

	token, e := issuer.New(testIssuer, selectiveClaims, headers, signer, timeOpts...)
	require.NoError(t, e)
	combinedFormatForIssuance, e := token.Serialize(false)
	require.NoError(t, e)

	combinedFormatForPresentation := combinedFormatForIssuance + common.CombinedFormatSeparator

	verifier, e := modeljwt.NewEd25519Verifier(pubKey)
	require.NoError(t, e)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		claims, err := Parse(combinedFormatForPresentation,
			WithSignatureVerifier(verifier),
			WithExpectedTypeHeader("JWT"))
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.Equal(t, 5, len(claims))
	})
}
