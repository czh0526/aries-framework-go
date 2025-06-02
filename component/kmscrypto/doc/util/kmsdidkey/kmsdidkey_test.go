package kmsdidkey

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptionPubKeyFromDIDKey(t *testing.T) {
	t.Parallel()

	t.Run("test Ed25519 key", func(t *testing.T) {
		didKeyEd25519 := "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyEd25519)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})

	t.Run("test X25519 key", func(t *testing.T) {
		didKeyX25519 := "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F"
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyX25519)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})

	t.Run("test P-256 key", func(t *testing.T) {
		didKeyP256 := "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyP256)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})

	t.Run("test P-384 key", func(t *testing.T) {
		didKeyP384 := "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyP384)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})

	t.Run("test P-521 key", func(t *testing.T) {
		didKeyP521 := "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7"
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyP521)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})

	t.Run("test P-256 uncompressed key", func(t *testing.T) {
		didKeyP256Uncompressed := "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z" //nolint:lll
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyP256Uncompressed)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})
	t.Run("test P-384 uncompressed key", func(t *testing.T) {
		didKeyP384Uncompressed := "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU" //nolint:lll
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyP384Uncompressed)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})
	t.Run("test P-521 uncompressed key", func(t *testing.T) {
		didKeyP521Uncompressed := "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK" //nolint:lll
		pubKey, err := EncryptionPubKeyFromDIDKey(didKeyP521Uncompressed)
		require.NoError(t, err)
		require.NotEmpty(t, pubKey)
	})
}
