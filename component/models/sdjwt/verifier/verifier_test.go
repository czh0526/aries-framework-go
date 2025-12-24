package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/holder"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/issuer"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"testing"
	"time"

	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer   = "https://example.com/issuer"
	testAudience = "https://test.com/verifier"
	testNonce    = "nonce"
	testSDAlg    = "sha-256"

	year = 365 * 24 * time.Hour
)

const (
	vcCombinedFormatForIssuance = `eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjEuNjczOTg3NTQ3ZSswOSwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEuNjczOTg3NTQ3ZSswOSwic3ViIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZDlYemtRbVJMQncxSXpfeHVGUmVLMUItRmpCdTdjT0N3RTlOR2F1d251SSJ9fSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbInBBdjJUMU10YmRXNGttUUdxT1VVRUpjQmdTZi1mSFRHV2xQVUV4aWlIbVEiLCI2dDlBRUJCQnEzalZwckJ3bGljOGhFWnNNSmxXSXhRdUw5c3ExMzJZTnYwIl0sImRlZ3JlZSI6eyJfc2QiOlsibzZzV2h4RjcxWHBvZ1cxVUxCbU90bjR1SXFGdjJ3ODF6emRuelJXdlpqYyIsIi1yRklXbU1YR3ZXX0FIYVEtODhpMy11ZzRUVjhLUTg5TjdmZmtneFc2X2MiXX0sImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIn0sImZpcnN0X25hbWUiOiJGaXJzdCBuYW1lIiwiaWQiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMTg3MiIsImluZm8iOiJJbmZvIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0xN1QyMjozMjoyNy40NjgxMDk4MTcrMDI6MDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJsYXN0X25hbWUiOiJMYXN0IG5hbWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX0.GcfSA6NkONxdsm5Lxj9-988eWx1ZvMz5vJ1uh2x8UK1iKIeQLmhsWpA_34RbtAm2HnuoxW4_ZGeiHBzQ1GLTDQ~WyJFWkVDRVZ1YWVJOXhZWmlWb3VMQldBIiwidHlwZSIsIkJhY2hlbG9yRGVncmVlIl0~WyJyMno1UzZMa25FRTR3TWwteFB0VEx3IiwiZGVncmVlIiwiTUlUIl0~WyJ2VkhfaGhNQy1aSUt5WFdtdDUyOWpnIiwic3BvdXNlIiwiZGlkOmV4YW1wbGU6YzI3NmUxMmVjMjFlYmZlYjFmNzEyZWJjNmYxIl0~WyJrVzh0WVVwbVl1VmRoZktFT050TnFnIiwibmFtZSIsIkpheWRlbiBEb2UiXQ` // nolint: lll
	vcSDJWT                     = `eyJhbGciOiJFZERTQSJ9.eyJpYXQiOjEuNjczOTg3NTQ3ZSswOSwiaXNzIjoiZGlkOmV4YW1wbGU6NzZlMTJlYzcxMmViYzZmMWMyMjFlYmZlYjFmIiwianRpIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzE4NzIiLCJuYmYiOjEuNjczOTg3NTQ3ZSswOSwic3ViIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiX3NkX2FsZyI6InNoYS0yNTYiLCJjbmYiOnsiandrIjp7ImNydiI6IkVkMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZDlYemtRbVJMQncxSXpfeHVGUmVLMUItRmpCdTdjT0N3RTlOR2F1d251SSJ9fSwiY3JlZGVudGlhbFN1YmplY3QiOnsiX3NkIjpbInBBdjJUMU10YmRXNGttUUdxT1VVRUpjQmdTZi1mSFRHV2xQVUV4aWlIbVEiLCI2dDlBRUJCQnEzalZwckJ3bGljOGhFWnNNSmxXSXhRdUw5c3ExMzJZTnYwIl0sImRlZ3JlZSI6eyJfc2QiOlsibzZzV2h4RjcxWHBvZ1cxVUxCbU90bjR1SXFGdjJ3ODF6emRuelJXdlpqYyIsIi1yRklXbU1YR3ZXX0FIYVEtODhpMy11ZzRUVjhLUTg5TjdmZmtneFc2X2MiXX0sImlkIjoiZGlkOmV4YW1wbGU6ZWJmZWIxZjcxMmViYzZmMWMyNzZlMTJlYzIxIn0sImZpcnN0X25hbWUiOiJGaXJzdCBuYW1lIiwiaWQiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMTg3MiIsImluZm8iOiJJbmZvIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0xN1QyMjozMjoyNy40NjgxMDk4MTcrMDI6MDAiLCJpc3N1ZXIiOiJkaWQ6ZXhhbXBsZTo3NmUxMmVjNzEyZWJjNmYxYzIyMWViZmViMWYiLCJsYXN0X25hbWUiOiJMYXN0IG5hbWUiLCJ0eXBlIjoiVmVyaWZpYWJsZUNyZWRlbnRpYWwifX0.GcfSA6NkONxdsm5Lxj9-988eWx1ZvMz5vJ1uh2x8UK1iKIeQLmhsWpA_34RbtAm2HnuoxW4_ZGeiHBzQ1GLTDQ`                                                                                                                                                                                                                                                                                                    // nolint:lll
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

	headers := docjose.Headers{
		docjose.HeaderType: "JWT",
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

	t.Run("success - VC sample", func(t *testing.T) {
		token, _, err := modeljwt.Parse(vcSDJWT, modeljwt.WithSignatureVerifier(&holder.NoopSignatureVerifier{}))
		require.NoError(t, err)

		var payload map[string]interface{}
		err = token.DecodeClaims(&payload)
		require.NoError(t, err)

		printObject(t, "SD-JWT Payload with VC", payload)

		vcCombinedFormatForPresentation := vcCombinedFormatForIssuance + common.CombinedFormatSeparator
		claims, err := Parse(vcCombinedFormatForPresentation, WithSignatureVerifier(&holder.NoopSignatureVerifier{}))
		require.NoError(t, err)

		printObject(t, "Disclosed Claims with VC", claims)
		require.Equal(t, 6, len(claims))
	})

	t.Run("success - valid SD-JWT times", func(t *testing.T) {
		now := time.Now()
		oneHourInThePast := now.Add(-time.Hour)
		oneHourInTheFuture := now.Add(time.Hour)

		tokenWithTimes, err := issuer.New(testIssuer, selectiveClaims, nil, signer,
			issuer.WithIssuedAt(josejwt.NewNumericDate(oneHourInThePast)),
			issuer.WithNotBefore(josejwt.NewNumericDate(oneHourInThePast)),
			issuer.WithExpiry(josejwt.NewNumericDate(oneHourInTheFuture)))
		require.NoError(t, err)

		cfIssuance, err := tokenWithTimes.Serialize(false)
		require.NoError(t, err)

		cfPresentation := fmt.Sprintf("%s%s", cfIssuance, common.CombinedFormatSeparator)

		claims, err := Parse(cfPresentation, WithSignatureVerifier(verifier))
		require.NoError(t, err)
		require.NotNil(t, claims)
	})
}

func TestHolderVerification(t *testing.T) {
	// 签发人的公私钥
	issuerPubKey, issuerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := modeljwt.NewEd25519Signer(issuerPrivateKey)
	verifier, err := modeljwt.NewEd25519Verifier(issuerPubKey)
	require.NoError(t, err)

	claims := map[string]interface{}{
		"given_name": "Albert",
		"last_name":  "Smith",
	}

	// 持有人的公私钥
	holderPubKey, holderPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	holderPublicJWK, err := jwksupport.JWKFromKey(holderPubKey)
	require.NoError(t, err)

	// 签发 SD-JWT
	token, err := issuer.New(testIssuer, claims, nil, signer,
		issuer.WithHolderPublicKey(holderPublicJWK))
	require.NoError(t, err)

	combinedFormatForIssuance, err := token.Serialize(false)
	require.NoError(t, err)

	// 持有人解析 SD-JWT
	_, err = holder.Parse(combinedFormatForIssuance, holder.WithSignatureVerifier(verifier))
	require.NoError(t, err)

	holderSigner := modeljwt.NewEd25519Signer(holderPrivateKey)

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	claimsToDisclose := []string{cfi.Disclosures[0]}

	tests := []struct {
		name    string
		headers docjose.Headers
	}{
		{
			name:    "holder binding",
			headers: nil,
		},
		{
			name: "holder binding",
			headers: map[string]interface{}{
				docjose.HeaderType: "kb+jwt",
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Run("success (required)", func(t *testing.T) {
				combinedFormatForPresentation, err := holder.CreatePresentation(
					combinedFormatForIssuance,
					claimsToDisclose,
					holder.WithHolderVerification(&holder.BindingInfo{
						Payload: holder.BindingPayload{
							Nonce:    testNonce,
							Audience: testAudience,
							IssuedAt: josejwt.NewNumericDate(time.Now()),
						},
						Headers: testCase.headers,
						Signer:  holderSigner,
					}))
				require.NoError(t, err)

				verifiedClaims, err := Parse(combinedFormatForPresentation,
					WithSignatureVerifier(verifier),
					WithHolderVerificationRequired(true),
					WithExpectedAudienceForHolderVerification(testAudience),
					WithExpectedNonceForHolderVerification(testNonce))
				require.NoError(t, err)
				require.NotNil(t, 3, len(verifiedClaims))
			})
		})

		t.Run("success - expected nonce and audience not specified", func(t *testing.T) {
			combinedFormatForPresentation, err := holder.CreatePresentation(
				combinedFormatForIssuance,
				claimsToDisclose,
				holder.WithHolderVerification(&holder.BindingInfo{
					Payload: holder.BindingPayload{
						Nonce:    testNonce,
						Audience: testAudience,
						IssuedAt: josejwt.NewNumericDate(time.Now()),
					},
					Headers: testCase.headers,
					Signer:  holderSigner,
				}))
			require.NoError(t, err)

			verifiedClaims, err := Parse(combinedFormatForPresentation,
				WithSignatureVerifier(verifier),
				WithLeewayForClaimsValidation(time.Hour))
			require.NoError(t, err)
			require.NotNil(t, 3, len(verifiedClaims))
		})
	}
}

func printObject(t *testing.T, name string, obj interface{}) {
	t.Helper()

	objBytes, err := json.Marshal(obj)
	require.NoError(t, err)

	prettyJSON, err := prettyPrint(objBytes)
	require.NoError(t, err)

	fmt.Println(name + ":")
	fmt.Println(prettyJSON)
}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}
