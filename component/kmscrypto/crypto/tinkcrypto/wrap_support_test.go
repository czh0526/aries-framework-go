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

// refJWKtoOKPKey 从JWK数据中提取 => 公钥的X数据 + 私钥
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

	tag, err := base64.RawURLEncoding.DecodeString("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ")
	require.NoError(t, err)

	cek, err := hex.DecodeString(
		"fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0")
	require.NoError(t, err)

	// bob 的中间密钥
	ref1PUBobData := &ref1PU{}
	err = json.Unmarshal([]byte(ecdh1puBobRef), ref1PUBobData)
	require.NoError(t, err)

	// charlie 的中间密钥
	ref1PUCharlieData := &ref1PU{}
	err = json.Unmarshal([]byte(ecdh1puCharlieRef), ref1PUCharlieData)
	require.NoError(t, err)

	// Alice, Bob, Charlie 的原始密钥
	_, alicePrivKeyRefOKP := refJWKtoOKPKey(t, aliceKeyRef)
	bobPubKeyRefOKP, _ := refJWKtoOKPKey(t, bobKeyRef)
	charliePubKeyRefOKP, _ := refJWKtoOKPKey(t, charlieKeyRef)
	// Alice 的中间密钥
	_, alicePrivKeyEPKRefOKP := refJWKtoOKPKey(t, aliceEPKRef)

	protectedHeaderRefJWK := &mockProtectedHeader{}
	err = json.Unmarshal([]byte(protectedHeadersRef), protectedHeaderRefJWK)
	require.NoError(t, err)

	apuRef, err := base64.RawURLEncoding.DecodeString(protectedHeaderRefJWK.Apu)
	require.NoError(t, err)

	apvRef, err := base64.RawURLEncoding.DecodeString(protectedHeaderRefJWK.Apv)
	require.NoError(t, err)

	// bob 中间密钥的 ze 值
	zeBobRef, err := hex.DecodeString(ref1PUBobData.ZeHex)
	require.NoError(t, err)

	// bob 中间密钥的 zs 值
	zsBobRef, err := hex.DecodeString(ref1PUBobData.ZsHex)
	require.NoError(t, err)

	// charlie 中间密钥的 ze 值
	zeCharlieRef, err := hex.DecodeString(ref1PUCharlieData.ZeHex)
	require.NoError(t, err)

	// charlie 中间密钥的 zs 值
	zsCharlieRef, err := hex.DecodeString(ref1PUCharlieData.ZsHex)
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
		require.Equal(t, ref1PUCharlieData.ZeHex, zeHEX)
		require.Equal(t, zeCharlieRef, ze)
	})

	t.Run("test derive Zs for Bob", func(t *testing.T) {
		zs, e := cryptoutil.DeriveECDHX25519(alicePrivKeyRefOKP, bobPubKeyRefOKP)
		require.NoError(t, e)

		zsHEX := hex.EncodeToString(zs)
		require.Equal(t, ref1PUBobData.ZsHex, zsHEX)
		require.Equal(t, zsBobRef, zs)
	})

	t.Run("test derive Zs for Charlie", func(t *testing.T) {
		zs, e := cryptoutil.DeriveECDHX25519(alicePrivKeyRefOKP, charliePubKeyRefOKP)
		require.NoError(t, e)

		zsHex := hex.EncodeToString(zs)
		require.Equal(t, ref1PUCharlieData.ZsHex, zsHex)
		require.Equal(t, zsCharlieRef, zs)
	})

	zBob, err := hex.DecodeString(ref1PUBobData.ZHex)
	require.NoError(t, err)
	require.Equal(t, append(zeBobRef, zsBobRef...), zBob)

	zCharlie, err := hex.DecodeString(ref1PUCharlieData.ZHex)
	require.NoError(t, err)
	require.Equal(t, append(zeCharlieRef, zsCharlieRef...), zCharlie)

	onePUKDFBobFromHex, err := hex.DecodeString(ref1PUBobData.Sender1PUKDFHex)
	require.NoError(t, err)

	onePUKDFCharlieFromHex, err := hex.DecodeString(ref1PUCharlieData.Sender1PUKDFHex)
	require.NoError(t, err)

	okpWrapper := okpKWSupport{}

	t.Run("test KDF for Bob", func(t *testing.T) {
		sender1PUWithBobKDF, e := okpWrapper.deriveSender1Pu(protectedHeaderRefJWK.Alg, apuRef, apvRef, tag,
			alicePrivKeyEPKRefOKP[:], alicePrivKeyRefOKP[:], bobPubKeyRefOKP[:], 32)
		require.NoError(t, e)
		require.Equal(t, onePUKDFBobFromHex, sender1PUWithBobKDF)
	})

	t.Run("test KDF for Charlie", func(t *testing.T) {
		sender1PUWithCharlieKDF, e := okpWrapper.deriveSender1Pu(protectedHeaderRefJWK.Alg, apuRef, apvRef, tag,
			alicePrivKeyEPKRefOKP[:], alicePrivKeyRefOKP[:], charliePubKeyRefOKP[:], 32)
		require.NoError(t, e)
		require.Equal(t, onePUKDFCharlieFromHex, sender1PUWithCharlieKDF)
	})

	ecKW := &ecKWSupport{}

	t.Run("test key wrap for Bob", func(t *testing.T) {
		bobAESBlock, err := ecKW.createPrimitive(onePUKDFBobFromHex)
		require.NoError(t, err)

		onePUKWBobFromB64, err := base64.RawURLEncoding.DecodeString(ref1PUBobData.Sender1PUKWB64)
		require.NoError(t, err)

		bobEncryptedKey, err := ecKW.wrap(bobAESBlock, cek)
		require.NoError(t, err)
		require.Equal(t, onePUKWBobFromB64, bobEncryptedKey)

		bobDecryptedCEK, err := ecKW.unwrap(bobAESBlock, onePUKWBobFromB64)
		require.NoError(t, err)
		require.Equal(t, cek, bobDecryptedCEK)
	})

	t.Run("test key wrap for Charlie", func(t *testing.T) {
		charlieAESBlock, err := ecKW.createPrimitive(onePUKDFCharlieFromHex)
		require.NoError(t, err)

		onePUKWCharlieFromB64, err := base64.RawURLEncoding.DecodeString(ref1PUCharlieData.Sender1PUKWB64)
		require.NoError(t, err)

		charlieEncryptedKey, err := ecKW.wrap(charlieAESBlock, cek)
		require.NoError(t, err)
		require.Equal(t, onePUKWCharlieFromB64, charlieEncryptedKey)

		charlieDecryptedCEK, err := ecKW.unwrap(charlieAESBlock, onePUKWCharlieFromB64)
		require.NoError(t, err)
		require.Equal(t, cek, charlieDecryptedCEK)
	})
}
