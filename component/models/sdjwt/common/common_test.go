package common

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/stretchr/testify/require"
	"testing"

	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
)

const additionalSDDisclosure = `WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0`
const additionalArrayElementDisclosure = `WyJjc3AteWZLWWNTYWlkUElUMHpyOFNRIiwiTWluYXMgVGlyaXRoIl0`

const testCombinedFormatForIssuance = `eyJhbGciOiJFZERTQSJ9.eyJfc2QiOlsicXF2Y3FuY3pBTWdZeDdFeWtJNnd3dHNweXZ5dks3OTBnZTdNQmJRLU51cyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImV4cCI6MTcwMzAyMzg1NSwiaWF0IjoxNjcxNDg3ODU1LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsIm5iZiI6MTY3MTQ4Nzg1NX0.vscuzfwcHGi04pWtJCadc4iDELug6NH6YK-qxhY1qacsciIHuoLELAfon1tGamHtuu8TSs6OjtLk3lHE16jqAQ~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           // nolint: lll
const testCombinedFormatForIssuanceV5 = `eyJhbGciOiJFZERTQSJ9.eyJfc2RfYWxnIjoic2hhLTI1NiIsImFkZHJlc3MiOnsiX3NkIjpbIlRaV0JRdlpTam1VemxRZ1AzZ2EydkFlYlV6cDhpU2NRNlBFT0gzSHQ1bm8iXSwiY2l0aWVzIjpbeyIuLi4iOiI0U1lCT3NMcVRURU42QnpTSV9NX0pyQ0NzWFJ0Y1BTbWNqV3ROMEdjU0dJIn0sIkVsIFBhc28iXSwiY291bnRyeUNvZGVzIjpbeyIuLi4iOiJab2hsNGd4OXd0czJBRlVrbmd1c3FleWJDUERWUVFLNHNPR3A4dWZHcWg4In0seyIuLi4iOiIxbVl4V1VZN2M5T1pEWlZnd0N6aUFuWkY1TDgzUzZaN2pGb1U2ck5vaEtzIn1dLCJleHRyYSI6eyJfc2QiOlsibXZtZVoxb3ZmY1RRTi01Q3A5YlhYcElKREd2THVkNVg4SVIyajctVUd0WSJdfSwicmVnaW9uIjoiU2FjaHNlbi1BbmhhbHQifSwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIifQ.l-xc_9hGQMHfkPmMeG_EQIZU5guVme9FSKgN58WqfBJcMvfrb9rTc2PHmxveerMTA2cjgJzM2OZgibQCxRePAg~WyJTUEh2T185NEsyWENVdVhSeURjcHJnIiwibG9jYWxpdHkiLCJTY2h1bHBmb3J0YSJd~WyJSaHh1bDBnd2x6cTlSNDg4ZV8tQ3B3IiwiVUEiXQ~WyJKQWlwWm5uSUM3ejAtZzJoNzZmc0FBIiwiUEwiXQ~WyIxdzZVNkRkSG9laFdUdG5UNG5iS3RnIiwiQWxidXF1ZXJxdWUiXQ~WyJVWnUxcjR5YnpfUGNiU3BRcTFpMllRIiwicmVjdXJzaXZlIix7Il9zZCI6WyJydjZNejBheXJZYWU1MHpWRXYtbExKNFZRRzhNMGFJdjJOVW1LVDRRRjVJIl19XQ~WyJoRWNiQmxZQ0ZSVGVtMG1uVXQzTVNnIiwia2V5MSIsInZhbHVlMSJd` // nolint: lll

// nolint: lll
const testSDJWT = `eyJhbGciOiJFZERTQSJ9.eyJfc2QiOlsicXF2Y3FuY3pBTWdZeDdFeWtJNnd3dHNweXZ5dks3OTBnZTdNQmJRLU51cyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImV4cCI6MTcwMzAyMzg1NSwiaWF0IjoxNjcxNDg3ODU1LCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsIm5iZiI6MTY3MTQ4Nzg1NX0.vscuzfwcHGi04pWtJCadc4iDELug6NH6YK-qxhY1qacsciIHuoLELAfon1tGamHtuu8TSs6OjtLk3lHE16jqAQ`

// nolint: lll
const specCombinedFormatForIssuance = `eyJhbGciOiAiUlMyNTYiLCAia2lkIjogImNBRUlVcUowY21MekQxa3pHemhlaUJhZzBZUkF6VmRsZnhOMjgwTmdIYUEifQ.eyJfc2QiOiBbIk5ZQ29TUktFWXdYZHBlNXlkdUpYQ3h4aHluRVU4ei1iNFR5TmlhcDc3VVkiLCAiU1k4bjJCYmtYOWxyWTNleEhsU3dQUkZYb0QwOUdGOGE5Q1BPLUc4ajIwOCIsICJUUHNHTlBZQTQ2d21CeGZ2MnpuT0poZmRvTjVZMUdrZXpicGFHWkNUMWFjIiwgIlprU0p4eGVHbHVJZFlCYjdDcWtaYkpWbTB3MlY1VXJSZU5UekFRQ1lCanciLCAibDlxSUo5SlRRd0xHN09MRUlDVEZCVnhtQXJ3OFBqeTY1ZEQ2bXRRVkc1YyIsICJvMVNBc0ozM1lNaW9POXBYNVZlQU0xbHh1SEY2aFpXMmtHZGtLS0JuVmxvIiwgInFxdmNxbmN6QU1nWXg3RXlrSTZ3d3RzcHl2eXZLNzkwZ2U3TUJiUS1OdXMiXSwgImlzcyI6ICJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsICJpYXQiOiAxNTE2MjM5MDIyLCAiZXhwIjogMTUxNjI0NzAyMiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIlJTQSIsICJuIjogInBtNGJPSEJnLW9ZaEF5UFd6UjU2QVdYM3JVSVhwMTFfSUNEa0dnUzZXM1pXTHRzLWh6d0kzeDY1NjU5a2c0aFZvOWRiR29DSkUzWkdGX2VhZXRFMzBVaEJVRWdwR3dyRHJRaUo5enFwcm1jRmZyM3F2dmtHanR0aDhaZ2wxZU0yYkpjT3dFN1BDQkhXVEtXWXMxNTJSN2c2SmcyT1ZwaC1hOHJxLXE3OU1oS0c1UW9XX21UejEwUVRfNkg0YzdQaldHMWZqaDhocFdObmJQX3B2NmQxelN3WmZjNWZsNnlWUkwwRFYwVjNsR0hLZTJXcWZfZU5HakJyQkxWa2xEVGs4LXN0WF9NV0xjUi1FR21YQU92MFVCV2l0U19kWEpLSnUtdlhKeXcxNG5IU0d1eFRJSzJoeDFwdHRNZnQ5Q3N2cWltWEtlRFRVMTRxUUwxZUU3aWhjdyIsICJlIjogIkFRQUIifX19.xqgKrDO6dK_oBL3fiqdcq_elaIGxM6Z-RyuysglGyddR1O1IiE3mIk8kCpoqcRLR88opkVWN2392K_XYfAuAmeT9kJVisD8ZcgNcv-MQlWW9s8WaViXxBRe7EZWkWRQcQVR6jf95XZ5H2-_KA54POq3L42xjk0y5vDr8yc08Reak6vvJVvjXpp-Wk6uxsdEEAKFspt_EYIvISFJhfTuQqyhCjnaW13X312MSQBPwjbHn74ylUqVLljDvqcemxeqjh42KWJq4C3RqNJ7anA2i3FU1kB4-KNZWsijY7-op49iL7BrnIBxdlAMrbHEkoGTbFWdl7Ki17GHtDxxa1jaxQg~WyJkcVR2WE14UzBHYTNEb2FHbmU5eDBRIiwgInN1YiIsICJqb2huX2RvZV80MiJd~WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJxUVdtakpsMXMxUjRscWhFTkxScnJ3IiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyJLVXhTNWhFX1hiVmFjckdBYzdFRnd3IiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyIzcXZWSjFCQURwSERTUzkzOVEtUml3IiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyIweEd6bjNNaXFzY3RaSV9PcERsQWJRIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJFUktNMENOZUZKa2FENW1UWFZfWDh3IiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0`

//go:embed testdata/full_disclosures_v5.json
var fullDisclosuresV5TestData []byte

type NoopSignatureVerifier struct {
}

func (sv *NoopSignatureVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

func TestGetDisclosureClaims(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuance)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		token, _, err := modeljwt.Parse(sdJWT.SDJWT, modeljwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		hash, err := GetCryptoHashFromClaims(token.Payload)
		require.NoError(t, err)

		disclosureClaims, err := GetDisclosureClaims(sdJWT.Disclosures, hash)
		require.NoError(t, err)
		require.Equal(t, 1, len(disclosureClaims))

		require.Equal(t, "given_name", disclosureClaims[0].Name)
		require.Equal(t, "John", disclosureClaims[0].Value)
	})

	t.Run("fill disclosures V5", func(t *testing.T) {
		var disData []string
		require.NoError(t, json.Unmarshal(fullDisclosuresV5TestData, &disData))

		parsed, err := GetDisclosureClaims(disData, crypto.SHA256)
		require.NoError(t, err)
		require.Equal(t, 10, len(parsed))
	})
}
