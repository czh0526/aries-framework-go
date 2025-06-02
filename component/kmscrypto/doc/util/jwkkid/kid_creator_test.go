package jwkkid

import (
	"crypto/ed25519"
	"crypto/rand"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_CreateKID(t *testing.T) {
	t.Run("test Ed25519 KID", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kid, err := CreateKID(pubKey, spikms.ED25519Type)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("test X25519 ECDH KID", func(t *testing.T) {
		var kid string

		randomKey := make([]byte, 32)
		_, err := rand.Read(randomKey)
		require.NoError(t, err)

		x25519Key := &spicrypto.PublicKey{
			Curve: "X25519",
			Type: ecdhpb.
		}
	})

}
