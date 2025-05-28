package jwkkid

import (
	"crypto/ed25519"
	"crypto/rand"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_CreateKID(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kid, err := CreateKID(pubKey, spikms.ED25519Type)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

}
