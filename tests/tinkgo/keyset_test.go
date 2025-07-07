package tinkgo

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"testing"
)

func TestEncryptKeySet(t *testing.T) {
	//kh, err := keyset.NewHandle(tink_aead.AES128CBCHMACSHA256KeyTemplate())
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)

	//kekKH, err := keyset.NewHandle(tink_aead.AES128CBCHMACSHA256KeyTemplate())
	kekKH, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	require.NoError(t, err)
	kekAEAD, err := aead.New(kekKH)
	require.NoError(t, err)

	// 需要追加的数据
	kekAAD := []byte("key set encryption data")

	// 写密钥
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = kh.WriteWithAssociatedData(writer, kekAEAD, kekAAD)
	require.NoError(t, err)

	// 读密钥
	reader := keyset.NewBinaryReader(bytes.NewReader(buf.Bytes()))
	handle, err := keyset.ReadWithAssociatedData(reader, kekAEAD, kekAAD)
	require.NoError(t, err)

	// 恢复 Primitive
	primitive, err := aead.New(handle)
	require.NoError(t, err)

	// 测试加密
	plaintext := []byte("message")
	aad := []byte("example encryption")
	ciphertext, err := primitive.Encrypt(plaintext, aad)
	require.NoError(t, err)

	// 测试解密
	decrypted, err := primitive.Decrypt(ciphertext, aad)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
