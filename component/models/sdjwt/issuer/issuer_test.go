package issuer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/PaesslerAG/jsonpath"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
	"testing"
)

const sampleVCFull = `
{
	"iat": 1673987547,
	"iss": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"jti": "http://example.edu/credentials/1872",
	"nbf": 1673987547,
	"sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	"vc": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1"
		],
		"credentialSubject": {
			"degree": {
				"degree": "MIT",
				"type": "BachelorDegree",
				"id": "some-id"
			},
			"name": "Jayden Doe",
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
		},
		"first_name": "First name",
		"id": "http://example.edu/credentials/1872",
		"info": "Info",
		"issuanceDate": "2023-01-17T22:32:27.468109817+02:00",
		"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
		"last_name": "Last name",
		"type": "VerifiableCredential"
	}
}`

const sampleSDJWTV5Full = `
{
	"iat": 1673987547,
	"iss": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"jti": "http://example.edu/credentials/1872",
	"nbf": 1673987547,
	"sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"credentialSubject": {
		"degree": {
			"degree": "MIT",
			"type": "BachelorDegree",
			"id": "some-id"
		},
		"name": "Jayden Doe",
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
	},
	"first_name": "First name",
	"id": "http://example.edu/credentials/1872",
	"info": "Info",
	"issuanceDate": "2023-01-17T22:32:27.468109817+02:00",
	"issuer": "did:example:76e12ec712ebc6f1c221ebfeb1f",
	"last_name": "Last name",
	"type": "VerifiableCredential"
}`

func TestNew(t *testing.T) {
	claims := createClaims()

	t.Run("Create SD-JWT without signing", func(t *testing.T) {
		token, err := New(issuer, claims, nil, &unsecuredJWTSigner{})
		require.NoError(t, err)

		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.NotNil(t, cfi)
		require.Equal(t, 1, len(cfi.Disclosures))

		var payload map[string]interface{}
		err = token.DecodeClaims(&payload)
		require.NoError(t, err)

		sdKey, ok := payload[common.SDKey].([]interface{})
		require.True(t, ok)
		require.Equal(t, 1, len(sdKey))
		require.Equal(t, "sha-256", payload[common.SDAlgorithmKey])
		require.Equal(t, issuer, payload["iss"])
	})

	t.Run("Create JWS with holder public key", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		holderJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		token, err := New(issuer, claims, nil, modeljwt.NewEd25519Signer(privKey),
			WithHolderPublicKey(holderJWK))
		require.NoError(t, err)
		combinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)
		require.Equal(t, 1, len(cfi.Disclosures))

		var parsedClaims map[string]interface{}
		err = verifyEd25519ViaGoJose(cfi.SDJWT, pubKey, &parsedClaims)
		require.NoError(t, err)

		parsedClaimsBytes, err := json.Marshal(parsedClaims)
		require.NoError(t, err)

		prettyJSON, err := prettyPrint(parsedClaimsBytes)
		require.NoError(t, err)

		fmt.Println(prettyJSON)
	})
}

func TestNewFromVC(t *testing.T) {
	_, issuerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := modeljwt.NewEd25519Signer(issuerPrivateKey)

	t.Run("success - structured claims + holder binding", func(t *testing.T) {
		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		var vc map[string]interface{}
		err = json.Unmarshal([]byte(sampleVCFull), &vc)
		require.NoError(t, err)

		token, err := NewFromVC(vc, nil, signer,
			WithHolderPublicKey(holderPublicJWK),
			WithStructuredClaims(true),
			WithNonSelectivelyDisclosableClaims([]string{"id"}))
		require.NoError(t, err)

		vcCombinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf("issuer SD-JWT: %s\n", vcCombinedFormatForIssuance)

		var vcWithSelectedDisclosures map[string]interface{}
		err = token.DecodeClaims(&vcWithSelectedDisclosures)
		require.NoError(t, err)

		printObject(t, "VC with selected disclosures", vcWithSelectedDisclosures)

		id, err := jsonpath.Get("$.vc.credentialSubject.id", vcWithSelectedDisclosures)
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", id)

		degreeType, err := jsonpath.Get("$.vc.credentialSubject.degree.type", vcWithSelectedDisclosures)
		require.NoError(t, err)
		require.Equal(t, "BachelorDegree", degreeType)

		degreeID, err := jsonpath.Get("$.vc.credentialSubject.degree.id", vcWithSelectedDisclosures)
		require.Error(t, err)
		require.Empty(t, degreeID)
		require.Contains(t, "unknown key id", err.Error())
	})

	t.Run("success - structured claims + holder binding + SD JWT V5 format", func(t *testing.T) {
		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		var vc map[string]interface{}
		err = json.Unmarshal([]byte(sampleSDJWTV5Full), &vc)
		require.NoError(t, err)

		token, err := NewFromVC(vc, nil, signer,
			WithHolderPublicKey(holderPublicJWK),
			WithStructuredClaims(true),
			WithNonSelectivelyDisclosableClaims([]string{"id", "degree.type"}),
			WithSDJWTVersion(common.SDJWTVersionV5))
		require.NoError(t, err)

		vcCombinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf("issuer SD-JWT: %s\n", vcCombinedFormatForIssuance)

		var vcWithSelectedDisclosures map[string]interface{}
		err = token.DecodeClaims(&vcWithSelectedDisclosures)
		require.NoError(t, err)

		printObject(t, "VC with selected disclosures", vcWithSelectedDisclosures)

		id, err := jsonpath.Get("$.credentialSubject.id", vcWithSelectedDisclosures)
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", id)

		degreeType, err := jsonpath.Get("$.credentialSubject.degree.type", vcWithSelectedDisclosures)
		require.NoError(t, err)
		require.Equal(t, "BachelorDegree", degreeType)

		degreeID, err := jsonpath.Get("$.credentialSubject.degree.id", vcWithSelectedDisclosures)
		require.Error(t, err)
		require.Empty(t, degreeID)
		require.Contains(t, "unknown key id", err.Error())
	})

	t.Run("success - flat claims + holder binding", func(t *testing.T) {
		holderPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		holderPublicJWK, err := jwksupport.JWKFromKey(holderPublicKey)
		require.NoError(t, err)

		var vc map[string]interface{}
		err = json.Unmarshal([]byte(sampleVCFull), &vc)
		require.NoError(t, err)

		token, err := NewFromVC(vc, nil, signer,
			WithHolderPublicKey(holderPublicJWK),
			WithNonSelectivelyDisclosableClaims([]string{"id"}))
		require.NoError(t, err)

		vcCombinedFormatForIssuance, err := token.Serialize(false)
		require.NoError(t, err)

		fmt.Printf("issuer SD-HWT: %s\n", vcCombinedFormatForIssuance)

		var vcWithSelectedDisclosures map[string]interface{}
		err = token.DecodeClaims(&vcWithSelectedDisclosures)
		require.NoError(t, err)

		printObject(t, "VC with selected disclosures", vcWithSelectedDisclosures)

		id, err := jsonpath.Get("$.vc.credentialSubject.id", vcWithSelectedDisclosures)
		require.NoError(t, err)
		require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", id)
	})
}

func createClaims() map[string]interface{} {
	claims := map[string]interface{}{
		"given_name": "John",
	}
	return claims
}

func verifyEd25519ViaGoJose(jws string, pubKey ed25519.PublicKey, claims interface{}) error {
	jwtToken, err := josejwt.ParseSigned(jws)
	if err != nil {
		return fmt.Errorf("parse VC from signed JWS: %w", err)
	}

	if err = jwtToken.Claims(pubKey, claims); err != nil {
		return fmt.Errorf("verify JWT signature: %w", err)
	}

	return nil
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

func prettyPrint(b []byte) (string, error) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, b, "", "  "); err != nil {
		return "", err
	}
	return pretty.String(), nil
}
