package jwk

import (
	"crypto/elliptic"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDecodePublicKey(t *testing.T) {
	t.Parallel()

	t.Run("attempt public key bytes from invalid JSON bytes", func(t *testing.T) {
		jwkJSON := []byte(`sdfsdfsd`)

		var j JWK
		err := json.Unmarshal(jwkJSON, &j)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
	t.Run("attempt public key byte from invalid curve", func(t *testing.T) {
		jwkJSON := []byte(`{
						"kty": "EC",
						"use": "enc",
						"crv": "sec12341",
						"kid": "sample@sample.id",
						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
						"y": "rIJO8RmkExUecJ5i15L9OC7rl7pwmYFR8QQgdM1ERWI",
						"alg": "ES256"
					}`)
		var j JWK
		err := json.Unmarshal(jwkJSON, &j)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported elliptic curve 'sec12341'")
	})

	t.Run("attempt public key bytes from invalid JSON bytes", func(t *testing.T) {
		jwkJSON := []byte(`{
						"kty": "EC",
						"use": "enc",
						"crv": "secp256k1",
						"kid": "sample@sample.id",
						"x": "",
						"y": "",
						"alg": "ES256"
					}`)
		var j JWK
		err := json.Unmarshal(jwkJSON, &j)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to read JWK: invalid JWK")
	})

	t.Run("attempt public key bytes from invalid JSON bytes", func(t *testing.T) {
		jwkJSON := []byte(`{
						"kty": "EC",
						"use": "enc",
						"crv": "secp256k1",
						"kid": "sample@sample.id",
						"x": "wQehEGTVCu32yp8IwTaBCqPUIYslyd-WoFRsfDKE9II",
						"y": "",
						"alg": "ES256"
					}`)
		var j JWK
		err := json.Unmarshal(jwkJSON, &j)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to read JWK: invalid JWK")
	})

	t.Run("attempt public key bytes from invalid JSON bytes", func(t *testing.T) {
		jwkJSON := []byte(`{
						"kty": "EC",
						"use": "enc",
						"crv": "secp256k1",
						"kid": "sample@sample.id",
						"x": "x",
						"y": "y",
						"alg": "ES256"
					}`)
		var j JWK
		err := json.Unmarshal(jwkJSON, &j)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to read JWK:")
	})
}

func TestCurveSize(t *testing.T) {
	require.Equal(t, 32, CurveSize(btcec.S256()))
	require.Equal(t, 32, CurveSize(elliptic.P256()))
	require.Equal(t, 28, CurveSize(elliptic.P224()))
	require.Equal(t, 48, CurveSize(elliptic.P384()))
	require.Equal(t, 66, CurveSize(elliptic.P521()))
}

func TestJWK_KeyType(t *testing.T) {
	t.Parallel()

	t.Run("key type `ED25519Type`", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "OKP",
				"use": "enc",
				"crv": "Ed25519",
				"kid": "sample@sample.id",
				"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
				"alg": "EdDSA"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ED25519Type, kt)
	})

	t.Run("test key X25519", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "OKP",
				"use": "enc",
				"crv": "X25519",
				"kid": "sample@sample.id",
				"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.X25519ECDHKWType, kt)
	})

	t.Run("test key secp 256k1", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "EC",
				"use": "enc",
				"crv": "secp256k1",
				"kid": "sample@sample.id",
				"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
				"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
				"alg": "ES256K"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ECDSASecp256k1TypeIEEEP1363, kt)
	})

	t.Run("test key EC P-256", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "EC",
				"use": "enc",
				"crv": "P-256",
				"kid": "sample@sample.id",
				"x": "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
				"y": "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
				"alg": "ES256"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ECDSAP256TypeIEEEP1363, kt)
	})

	t.Run("test key EC P384", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "EC",
				"kid": "sample@sample.id",
				"crv": "P-384",
				"x": "SNJT8Q-irydV5yppI-blGNuRTPf8sCYuL_tO92SLrufdlEgDll9cRuBLACrlBz2x",
				"y": "zIYfra2_y2hnc35sIwA1jiDx5rKmG3mX6162HkAodTJIpUYxw2rz1qHiwVcaU2tY",
				"alg": "ES384"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ECDSAP384TypeIEEEP1363, kt)
	})

	t.Run("test key EC P-521", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "EC",
				"kid": "sample@sample.id",
				"crv": "P-521",
				"d": "AfcmEHp9Nd_X005hBoKEs8bvMzIH0OMYodQUw8xRWpUGOq31cyXV1dUvX-S8uSaBIbh2w-fy_OaolBmvTe3Il5Rw",
				"x": "AMIjmQpOT7oz5e8CJZQVi3cxCdF0gdmnNE8qmi5Y3_1-6gRzHoaXGs_TBcAvNgD8UCYhk3FWA8aLChJ9BjEUi44m",
				"y": "AIfNzFdbyI1rfRrcY7orl3wTXT-C_kWhyWdr3K3rSS8WbwXhqg9jb29iEoE8izpCnuoJbC_FsMf2WbI_1iNomfB4",
				"alg": "ES512"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ECDSAP521TypeIEEEP1363, kt)
	})

	t.Run("test key RSA 256", func(t *testing.T) {
		jwkJSON := []byte(`{
					"kty": "RSA",
					"e": "AQAB",
					"use": "enc",
					"kid": "sample@sample.id",
					"alg": "RS256",
					"n": "1hOl09BUnwY7jFBqoZKa4XDmIuc0YFb4y_5ThiHhLRW68aNG5Vo23n3ugND2GK3PsguZqJ_HrWCGVuVlKTmFg` +
			`JWQD9ZnVcYqScgHpQRhxMBi86PIvXR01D_PWXZZjvTRakpvQxUT5bVBdWnaBHQoxDBt0YIVi5a7x-gXB1aDlts4RTMpfS9BPmEjX` +
			`4lciozwS6Ow_wTO3C2YGa_Our0ptIxr-x_3sMbPCN8Fe_iaBDezeDAm39xCNjFa1E735ipXA4eUW_6SzFJ5-bM2UKba2WE6xUaEa5G1` +
			`MDDHCG5LKKd6Mhy7SSAzPOR2FTKYj89ch2asCPlbjHTu8jS6Iy8"
				}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.RSAPS256Type, kt)
	})

	t.Run("test ed25519 with []byte key material", func(t *testing.T) {
		jwkJSON := []byte(`{
				"kty": "OKP",
				"use": "enc",
				"crv": "Ed25519",
				"kid": "sample@sample.id",
				"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
				"alg": "EdDSA"
			}`)

		j := JWK{}
		e := j.UnmarshalJSON(jwkJSON)
		require.NoError(t, e)

		pkb, err := j.PublicKeyBytes()
		require.NoError(t, err)

		j.Key = pkb
		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ED25519Type, kt)
	})

	t.Run("test secp256k1 with []byte key material", func(t *testing.T) {
		jwkJSON := `{
			"kty": "EC",
			"use": "enc",
			"crv": "secp256k1",
			"kid": "sample@sample.id",
			"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
			"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
			"alg": "ES256K"
		}`

		j := JWK{}
		e := j.UnmarshalJSON([]byte(jwkJSON))
		require.NoError(t, e)

		pkb, err := j.PublicKeyBytes()
		require.NoError(t, err)

		j.Key = pkb

		kt, e := j.KeyType()
		require.NoError(t, e)
		require.Equal(t, spikms.ECDSASecp256k1TypeIEEEP1363, kt)
	})
}
