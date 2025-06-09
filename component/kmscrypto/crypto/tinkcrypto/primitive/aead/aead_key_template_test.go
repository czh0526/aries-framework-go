package aead

import (
	"bytes"
	"github.com/stretchr/testify/require"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"testing"
)

func TestKeyTemplates(t *testing.T) {

	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "AEAD_AES_128_CBC_HMAC_SHA_256",
			template: AES128CBCHMACSHA256KeyTemplate(),
		},
		{
			name:     "AEAD_AES_192_CBC_HMAC_SHA_384",
			template: AES192CBCHMACSHA384KeyTemplate(),
		},
		{
			name:     "AEAD_AES_256_CBC_HMAC_SHA_384",
			template: AES256CBCHMACSHA384KeyTemplate(),
		},
		{
			name:     "AEAD_AES_256_CBC_HMAC_SHA_512",
			template: AES256CBCHMACSHA512KeyTemplate(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kh, err := keyset.NewHandle(tc.template)
			require.NoError(t, err)

			testEncryptDecrypt(t, kh)
		})
	}
}

func testEncryptDecrypt(t *testing.T, kh *keyset.Handle) {
	t.Helper()

	primitive, err := tinkaead.New(kh)
	require.NoError(t, err, "aead.New(handle) failed")

	testInputs := []struct {
		plaintext []byte
		aad1      []byte
		aad2      []byte
	}{
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		},
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      []byte(""),
		},
		{
			plaintext: []byte(""),
			aad1:      nil,
			aad2:      nil,
		},
		{
			plaintext: nil,
			aad1:      []byte("extra data to authenticate"),
			aad2:      []byte("extra data to authenticate"),
		},
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      []byte(""),
			aad2:      nil,
		},
		{
			plaintext: []byte("some data to encrypt"),
			aad1:      nil,
			aad2:      []byte(""),
		},
	}

	for _, ti := range testInputs {
		ciphertext, err := primitive.Encrypt(ti.plaintext, ti.aad1)
		require.NoError(t, err, "encryption failed")

		decrypted, err := primitive.Decrypt(ciphertext, ti.aad2)
		require.NoError(t, err, "decryption failed")

		if !bytes.Equal(ti.plaintext, decrypted) {
			t.Fatalf("decryptd data doesn't match plaintext, got: %q, want: %q", decrypted, ti.plaintext)
		}
	}
}
