package kmsdidkey

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptionPubKeyFromDIDKey(t *testing.T) {
	t.Run("test ED25519 key", func(t *testing.T) {
		didKeyED25519 := "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyED25519)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})
	t.Run("test X25519 key", func(t *testing.T) {

	})
	t.Run("test P-256 key", func(t *testing.T) {

	})
	t.Run("test P-384 key", func(t *testing.T) {

	})
	t.Run("test P-521 key", func(t *testing.T) {

	})
	t.Run("test P-256 uncompressed key", func(t *testing.T) {

	})
	t.Run("test P-384 uncompressed key", func(t *testing.T) {

	})
	t.Run("test P-521 uncompressed key", func(t *testing.T) {

	})
}
