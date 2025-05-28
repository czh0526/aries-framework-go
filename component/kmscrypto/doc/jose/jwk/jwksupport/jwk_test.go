package jwksupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	jwkSecp256k1_pubKey = []byte(`{
		"kty": "EC",
		"use": "enc",
		"crv": "secp256k1",
		"kid": "sample@sample.id",
		"x": "YRrvJocKf39GpdTnd-zBFE0msGDqawR-Cmtc6yKoFsM",
		"y": "kE-dMH9S3mxnTXo0JFEhraCU_tVYFDfpu9tpP1LfVKQ",
		"alg": "ES256K"
	}`)

	jwkSecp256k1_privKey = []byte(`{
		"kty": "EC",
		"d": "Lg5xrN8Usd_T-MfqBIs3bUWQCNsXY8hGU-Ru3Joom8E",
		"use": "sig",
		"crv": "secp256k1",
		"kid": "sample@sample.id",
		"x": "dv6X5DheBaFWR2H_yv9pUI2dcmL2XX8m7zgFc9Coaqg",
		"y": "AUVSmytVWP350kV1RHhQ6AcCWaJj8AFt4aNLlDws7C4",
		"alg": "ES256K"
	}`)

	jwkEd25519Json = []byte(`{
		"kty": "OKP",
		"use": "enc",
		"crv": "Ed25519",
		"kid": "sample@sample.id",
		"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8",
		"alg": "EdDSA"
	}`)

	jwkX25519Json = []byte(`{
		"kty": "OKP",
		"use": "enc",
		"crv": "X25519",
		"kid": "sample@sample.id",
		"x": "sEHL6KXs8bUz9Ss2qSWWjhhRMHVjrog0lzFENM132R8"
	}`)

	jwkP256Json = []byte(`{
		"kty": "EC",
		"use": "enc",
		"crv": "P-256",
		"kid": "sample@sample.id",
		"x": "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
		"y": "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
		"alg": "ES256"
	}`)

	jwkP384Json = []byte(`{
		"kty": "EC",
		"use": "enc",
		"crv": "P-384",
		"kid": "sample@sample.id",
		"x": "GGFw14WnABx5S__MLwjy7WPgmPzCNbygbJikSqwx1nQ7APAiIyLeiAeZnAFQSr8C",
		"y": "Bjev4lkaRbd4Ery0vnO8Ox4QgIDGbuflmFq0HhL-QHIe3KhqxrqZqbQYGlDNudEv",
		"alg": "ES384"
	}`)

	jwkP521Json = []byte(`{
		"kty": "EC",
		"use": "enc",
		"crv": "P-521",
		"kid": "sample@sample.id",
		"x": "AZi-AxJkB09qw8dBnNrz53xM-wER0Y5IYXSEWSTtzI5Sdv_5XijQn9z-vGz1pMdww-C75GdpAzp2ghejZJSxbAd6",
		"y": "AZzRvW8NBytGNbF3dyNOMHB0DHCOzGp8oYBv_ZCyJbQUUnq-TYX7j8-PlKe9Ce5acxZzrcUKVtJ4I8JgI5x9oXIW",
		"alg": "ES521"
	}`)
)

func TestDecodeJWK(t *testing.T) {

	t.Parallel()

	t.Run("test secp256k1 public key", func(t *testing.T) {
		var jwkKey jwk.JWK

		// jwk反序列化
		err := json.Unmarshal(jwkSecp256k1_pubKey, &jwkKey)
		require.NoError(t, err)

		// 提取公钥
		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		// jwk序列化
		jwkBytes, err := json.Marshal(jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// 测试 key => jwk
		jwkSecp256k1, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotNil(t, jwkSecp256k1)
		require.Equal(t, "secp256k1", jwkSecp256k1.Crv)
	})

	t.Run("test secp256k1 private key", func(t *testing.T) {
		var jwkKey jwk.JWK

		// jwk反序列化
		err := json.Unmarshal(jwkSecp256k1_privKey, &jwkKey)
		require.NoError(t, err)

		// 提取公钥
		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		// jwk序列化
		jwkBytes, err := json.Marshal(jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// 测试 key => jwk
		jwkSecp256k1, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotNil(t, jwkSecp256k1)
		require.Equal(t, "secp256k1", jwkSecp256k1.Crv)
	})

	t.Run("test Ed25519 JWK", func(t *testing.T) {
		var jwkKey jwk.JWK

		// jwk反序列化
		err := json.Unmarshal(jwkEd25519Json, &jwkKey)
		require.NoError(t, err)

		// 提取公钥
		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		// jwk序列化
		jwkBytes, err := json.Marshal(jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// 测试 key => jwk
		jwkEd25519, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotNil(t, jwkEd25519)
		require.Equal(t, "Ed25519", jwkEd25519.Crv)
		require.Equal(t, ed25519.PublicKeySize, len(jwkEd25519.Key.(ed25519.PublicKey)))
		require.Equal(t, okpKty, jwkEd25519.Kty)
	})

	t.Run("test X25519 JWK", func(t *testing.T) {
		var jwkKey jwk.JWK

		// 测试反序列化
		err := json.Unmarshal(jwkX25519Json, &jwkKey)
		require.NoError(t, err)

		// 测试提取公钥
		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		// 测试序列化
		jwkBytes, err := json.Marshal(&jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// X25519中，jwkKey.Key 是 []byte
		jwkX25519, err := JWKFromX25519Key(jwkKey.Key.([]byte))
		require.NoError(t, err)
		require.NotNil(t, jwkX25519)
		require.Equal(t, x25519Crv, jwkX25519.Crv)
		require.Equal(t, cryptoutil.Curve25519KeySize, len(jwkX25519.Key.([]byte)))
		require.Equal(t, okpKty, jwkX25519.Kty)
	})

	t.Run("test EC P-256 JWK", func(t *testing.T) {
		var jwkKey jwk.JWK

		err := json.Unmarshal(jwkP256Json, &jwkKey)
		require.NoError(t, err)

		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		jwkBytes, err := json.Marshal(&jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// EC P-256中, jwkKey.Key 是 ecdsa.PublicKey 或者 ecdsa.PrivateKey
		jwkP256, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotNil(t, jwkP256)
		require.Equal(t, elliptic.P256().Params().Name, jwkP256.Crv)
		require.Equal(t, "EC", jwkP256.Kty)
		ecKey, ok := jwkP256.Key.(*ecdsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, "JR7nhI47w7bxrNkp7Xt1nbmozNn-RB2Q-PWi7KHT8J0",
			base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
		require.Equal(t, "iXmKtH0caOgB1vV0CQwinwK999qdDvrssKhdbiAz9OI",
			base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))
	})

	t.Run("test EC P-384 JWK", func(t *testing.T) {
		var jwkKey jwk.JWK

		err := json.Unmarshal(jwkP384Json, &jwkKey)
		require.NoError(t, err)

		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		jwkBytes, err := json.Marshal(&jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// EC P-384中, jwkKey.Key 是 ecdsa.PublicKey 或者 ecdsa.PrivateKey
		jwkP384, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotNil(t, jwkP384)
		require.Equal(t, elliptic.P384().Params().Name, jwkP384.Crv)
		require.Equal(t, "EC", jwkP384.Kty)
		ecKey, ok := jwkP384.Key.(*ecdsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, "GGFw14WnABx5S__MLwjy7WPgmPzCNbygbJikSqwx1nQ7APAiIyLeiAeZnAFQSr8C",
			base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
		require.Equal(t, "Bjev4lkaRbd4Ery0vnO8Ox4QgIDGbuflmFq0HhL-QHIe3KhqxrqZqbQYGlDNudEv",
			base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))
	})

	t.Run("test EC P-521 JWK", func(t *testing.T) {
		var jwkKey jwk.JWK

		err := json.Unmarshal(jwkP521Json, &jwkKey)
		require.NoError(t, err)

		pkBytes, err := jwkKey.PublicKeyBytes()
		require.NoError(t, err)
		require.NotEmpty(t, pkBytes)

		jwkBytes, err := json.Marshal(&jwkKey)
		require.NoError(t, err)
		require.NotEmpty(t, jwkBytes)

		// EC P-521中, jwkKey.Key 是 ecdsa.PublicKey 或者 ecdsa.PrivateKey
		jwkP521, err := JWKFromKey(jwkKey.Key)
		require.NoError(t, err)
		require.NotEmpty(t, jwkP521)
		require.Equal(t, elliptic.P521().Params().Name, jwkP521.Crv)
		require.Equal(t, "EC", jwkP521.Kty)
		ecKey, ok := jwkP521.Key.(*ecdsa.PublicKey)
		require.True(t, ok)
		require.Equal(t, "AZi-AxJkB09qw8dBnNrz53xM-wER0Y5IYXSEWSTtzI5Sdv_5XijQn9z-vGz1pMdww-C75GdpAzp2ghejZJSxbAd6",
			base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()))
		require.Equal(t, "AZzRvW8NBytGNbF3dyNOMHB0DHCOzGp8oYBv_ZCyJbQUUnq-TYX7j8-PlKe9Ce5acxZzrcUKVtJ4I8JgI5x9oXIW",
			base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()))
	})
}
