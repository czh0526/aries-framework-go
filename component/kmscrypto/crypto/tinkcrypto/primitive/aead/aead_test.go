package aead

import (
	"encoding/base64"
	"fmt"
	"github.com/stretchr/testify/require"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"testing"
)

func TestAEADInit(t *testing.T) {
	_, err := registry.GetKeyManager(aesCBCHMACAEADTypeURL)
	require.NoError(t, err)
}

func TestAES128CBCHMACSHA256KeyTemplate(t *testing.T) {
	kh, err := keyset.NewHandle(AES128CBCHMACSHA256KeyTemplate())
	require.NoError(t, err)

	a, err := tinkaead.New(kh)
	require.NoError(t, err)

	msg := []byte("this message need to be encrypted")
	aad := []byte("this data needs to be authenticated, but not encrypted")

	ct, err := a.Encrypt(msg, aad)
	require.NoError(t, err)

	pt, err := a.Decrypt(ct, aad)
	require.NoError(t, err)

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(pt))
	fmt.Printf("Orignal plaintext: %s\n", msg)
	fmt.Printf("Decrypted ciphertext: %s\n", pt)
}

func TestAES256CBCHMACSHA521KeyTemplate(t *testing.T) {
	kh, err := keyset.NewHandle(AES256CBCHMACSHA512KeyTemplate())
	require.NoError(t, err)

	a, err := tinkaead.New(kh)
	require.NoError(t, err)

	msg := []byte("this message need to be encrypted")
	aad := []byte("this data needs to be authenticated, but not encrypted")

	ct, err := a.Encrypt(msg, aad)
	require.NoError(t, err)

	pt, err := a.Decrypt(ct, aad)
	require.NoError(t, err)

	fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(pt))
	fmt.Printf("Orignal plaintext: %s\n", msg)
	fmt.Printf("Decrypted ciphertext: %s\n", pt)
}
