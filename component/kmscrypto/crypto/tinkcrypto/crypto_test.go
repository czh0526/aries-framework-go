package tinkcrypto

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1"
	"github.com/stretchr/testify/require"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	tinkaeadsubtle "github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
	"testing"
)

const testMessage = "test message"

func TestCrypto_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name         string
		ivSize       int
		aeadTemplate *tinkpb.KeyTemplate
	}{
		{
			name:         "test AES256GCM encryption",
			ivSize:       tinkaeadsubtle.AESGCMIVSize,
			aeadTemplate: tinkaead.AES256GCMKeyTemplate(),
		},
		{
			name:         "test AES128CBCHMACSHA256 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES128CBCHMACSHA256KeyTemplate(),
		},
		{
			name:         "test AES192CBCHMACSHA384 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES192CBCHMACSHA384KeyTemplate(),
		},
		{
			name:         "test AES256CBCHMACSHA5384 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES256CBCHMACSHA384KeyTemplate(),
		},
		{
			name:         "test AES256CBCHMACSHA512 encryption",
			ivSize:       subtle.AESCBCIVSize,
			aeadTemplate: aead.AES256CBCHMACSHA512KeyTemplate(),
		},
	}

	t.Parallel()

	for _, test := range tests {
		tc := test
		t.Run(tc.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.aeadTemplate)
			require.NoError(t, err)
			km := keyset.NewManagerFromHandle(kh)

			c := Crypto{}
			msg := []byte(testMessage)
			aad := []byte("some additional data")
			cipherText, err := c.Encrypt(msg, aad, kh)
			require.NoError(t, err)
			require.NotEmpty(t, cipherText)

			// 新增加一个 Key
			keyId2, err := km.Add(tc.aeadTemplate)
			require.NoError(t, err)
			require.NotEmpty(t, keyId2)
			// 再新增一个 Key
			keyId3, err := km.Add(tc.aeadTemplate)
			require.NoError(t, err)
			require.NotEmpty(t, keyId3)
			// 设置 PrimaryKey
			err = km.SetPrimary(keyId3)
			require.NoError(t, err)
			kh, err = km.Handle()
			require.NoError(t, err)

			plainText, err := c.Decrypt(cipherText, aad, kh)
			require.NoError(t, err)
			require.Equal(t, msg, plainText)

			plainText, err = c.Decrypt([]byte("bad cipher"), aad, kh)
			require.Error(t, err)
			require.Empty(t, plainText)
		})
	}
}

func TestCrypto_SignVerify(t *testing.T) {
	t.Run("test with Ed25519 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ED25519KeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-256 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP256KeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with P-384 signature", func(t *testing.T) {
		kh, err := keyset.NewHandle(signature.ECDSAP384SHA512KeyTemplate())
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})

	t.Run("test with secp256k1 signature", func(t *testing.T) {
		derTemplate, err := secp256k1.DERKeyTemplate()
		require.NoError(t, err)

		kh, err := keyset.NewHandle(derTemplate)
		require.NoError(t, err)

		c := Crypto{}
		msg := []byte(testMessage)
		sig, err := c.Sign(msg, kh)
		require.NoError(t, err)

		pubKH, err := kh.Public()
		require.NoError(t, err)

		err = c.Verify(sig, msg, pubKH)
		require.NoError(t, err)
	})
}

func TestCrypto_ComputeVerifyMAC(t *testing.T) {
	t.Run("test with compute MAC", func(t *testing.T) {
		kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)
		require.NotNil(t, kh)

		c := Crypto{}
		msg := []byte(testMessage)
		macBytes, err := c.ComputeMAC(msg, kh)
		require.NoError(t, err)
		require.NotEmpty(t, macBytes)

		err = c.VerifyMAC(macBytes, msg, kh)
		require.NoError(t, err)
	})
}
