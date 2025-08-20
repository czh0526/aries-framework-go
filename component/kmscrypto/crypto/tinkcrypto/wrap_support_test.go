package tinkcrypto

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"testing"
)

type ref1PU struct {
	ZeHex           string `json:"zeHex,omitempty"`
	ZsHex           string `json:"zsHex,omitempty"`
	ZHex            string `json:"zHex,omitempty"`
	Sender1PUKDFHex string `json:"sender1puKdfHex,omitempty"`
	Sender1PUKWB64  string `json:"sender1puKwB64,omitempty"`
}

type mockKey struct {
	Kty string `json:"kty,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}

type mockProtectedHeader struct {
	Alg string  `json:"alg,omitempty"`
	Enc string  `json:"enc,omitempty"`
	Apu string  `json:"apu,omitempty"`
	Apv string  `json:"apv,omitempty"`
	Epk mockKey `json:"epk,omitempty"`
}

func refJWKtoOKPKey(t *testing.T, jwkM string) (*[chacha20poly1305.KeySize]byte, *[chacha20poly1305.KeySize]byte) {
	t.Helper()

	jwk := &mockKey{}
	err := json.Unmarshal([]byte(jwkM), jwk)
	require.NoError(t, err)

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	require.NoError(t, err)

	x32 := new([chacha20poly1305.KeySize]byte)
	copy(x32[:], x)

	d32 := new([chacha20poly1305.KeySize]byte)
	copy(d32[:], d)

	return x32, d32
}

var (
	//go:embed testdata/alice_key_ref.json
	aliceKeyRef string
	//go:embed testdata/bob_key_ref.json
	bobKeyRef string
	//go:embed testdata/charlie_key_ref.json
	charlieKeyRef string
	//go:embed testdata/alice_epk_ref.json
	aliceEPKRef string
	//go:embed testdata/protected_headers_ref.json
	protectedHeadersRef string
	//go:embed testdata/ecdh_1pu_bob.json
	ecdh1puBobRef string
	//go:embed testdata/ecdh_1pu_charlie.json
	ecdh1puCharlieRef string
)

func TestDeriveReferenceKey(t *testing.T) {
	var err error

	//tag, err := base64.RawURLEncoding.DecodeString("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ")
	//require.NoError(t, err)
	//
	//cek, err := hex.DecodeString(
	//	"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0")
	//require.NoError(t, err)

	ref1PUBobData := &ref1PU{}
	err = json.Unmarshal([]byte(ecdh1puBobRef), ref1PUBobData)
	require.NoError(t, err)

	ref1PUCharlieData := &ref1PU{}
	err = json.Unmarshal([]byte(ecdh1puCharlieRef), ref1PUCharlieData)
	require.NoError(t, err)

	//_, alicePrivKeyRefOKP := refJWKtoOKPKey(t, aliceKeyRef)
	bobPubKeyRefOKP, _ := refJWKtoOKPKey(t, bobKeyRef)
	charliePubKeyRefOKP, _ := refJWKtoOKPKey(t, charlieKeyRef)
	_, alicePrivKeyEPKRefOKP := refJWKtoOKPKey(t, aliceKeyRef)

	protectedHeaderRefJWK := &mockProtectedHeader{}
	err = json.Unmarshal([]byte(protectedHeadersRef), protectedHeaderRefJWK)
	require.NoError(t, err)

	//apuRef, err := base64.RawURLEncoding.DecodeString(protectedHeaderRefJWK.Apu)
	//require.NoError(t, err)
	//
	//apvRef, err := base64.RawURLEncoding.DecodeString(protectedHeaderRefJWK.Apv)
	//require.NoError(t, err)

	zeBobRef, err := hex.DecodeString(ref1PUBobData.ZeHex)
	require.NoError(t, err)

	zeCharlieRef, err := hex.DecodeString(ref1PUCharlieData.ZeHex)
	require.NoError(t, err)

	t.Run("test derive Ze for Bob", func(t *testing.T) {
		ze, e := cryptoutil.DeriveECDHX25519(alicePrivKeyEPKRefOKP, bobPubKeyRefOKP)
		require.NoError(t, e)
		require.Equal(t, zeBobRef, ze)

		zeHEX := hex.EncodeToString(ze)
		require.Equal(t, ref1PUBobData.ZeHex, zeHEX)
	})

	t.Run("test derive Ze for Charlie", func(t *testing.T) {
		ze, e := cryptoutil.DeriveECDHX25519(alicePrivKeyEPKRefOKP, charliePubKeyRefOKP)
		require.NoError(t, e)

		zeHEX := hex.EncodeToString(ze)
		require.Equal(t, ref1PUBobData.ZeHex, zeHEX)
		require.Equal(t, zeCharlieRef, ze)
	})
}
