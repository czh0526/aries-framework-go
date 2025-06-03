package jwkkid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_CreateKID(t *testing.T) {
	t.Run("test Ed25519 KID", func(t *testing.T) {
		// 构建一个 Public Key 对象
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Public Key => KID
		kid, err := CreateKID(pubKey, spikms.ED25519Type)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("test X25519 ECDH KID", func(t *testing.T) {
		var kid string

		randomKey := make([]byte, 32)
		_, err := rand.Read(randomKey)
		require.NoError(t, err)

		// 构建一个 Public Key 对象
		x25519Key := &spicrypto.PublicKey{
			Curve: "X25519",
			Type:  ecdhpb.KeyType_OKP.String(),
			X:     randomKey,
		}

		mX25519Key, err := json.Marshal(x25519Key)
		require.NoError(t, err)

		kid, err = CreateKID(mX25519Key, spikms.X25519ECDHKWType)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("test P-256 DER format KID", func(t *testing.T) {
		var kid string

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubECKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err)

		kid, err = CreateKID(pubECKeyBytes, spikms.ECDSAP256DER)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("test P-256 IEEE-P1363 format KID", func(t *testing.T) {
		var kid string

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		pubECKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
		require.NoError(t, err)

		kid, err = CreateKID(pubECKeyBytes, spikms.ECDSAP256TypeIEEEP1363)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("test secp256k1 DER format KID", func(t *testing.T) {
		var kid string

		secp256k1Key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		pubECKeyBytes := elliptic.Marshal(secp256k1Key.Curve, secp256k1Key.X, secp256k1Key.Y)
		kid, err = CreateKID(pubECKeyBytes, spikms.ECDSASecp256k1TypeIEEEP1363)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("test secp256k1 IEEE-P1363 format KID", func(t *testing.T) {
		var kid string

		secp256k1Key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		pubECKeyBytes := elliptic.Marshal(secp256k1Key.Curve, secp256k1Key.X, secp256k1Key.Y)
		kid, err = CreateKID(pubECKeyBytes, spikms.ECDSASecp256k1TypeIEEEP1363)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})
}
