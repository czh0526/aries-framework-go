package hkdf

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
	"testing"
)

func TestMasterLock_New(t *testing.T) {
	keySize := sha256.New().Size()
	goodPassphrase := "somepassphrase"

	salt := make([]byte, keySize)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	// 错误的构建一个 MasterLock (Hash函数不支持)
	mkLockBad, err := NewMasterLock(goodPassphrase, sha512.New, salt)
	require.Error(t, err)
	require.Empty(t, mkLockBad)

	// 错误的构建一个 MasterLock（密码为空）
	mkLockBad, err = NewMasterLock("", sha256.New, salt)
	require.Error(t, err)
	require.Empty(t, mkLockBad)

	// 错误的构建一个 MasterLock（Hash函数为空）
	mkLockBad, err = NewMasterLock(goodPassphrase, nil, salt)
	require.Error(t, err)
	require.Empty(t, mkLockBad)

	// 1）正常的构建一个 MasterLock
	mkLock, err := NewMasterLock(goodPassphrase, sha256.New, salt)
	require.NoError(t, err)
	require.NotNil(t, mkLock)
}

func TestMasterLock_EncryptDecrypt(t *testing.T) {
	keySize := sha256.New().Size()
	testKey := random.GetRandomBytes(uint32(keySize))
	goodPassphrase := "somepassphrase"

	salt := make([]byte, keySize)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	// 1）正常的构建一个 MasterLock
	mkLock, err := NewMasterLock(goodPassphrase, sha256.New, salt)
	require.NoError(t, err)

	// 2）对 Key 进行正常加密
	encryptedMk, err := mkLock.Encrypt("", &secretlock.EncryptRequest{
		Plaintext: string(testKey),
	})
	require.NoError(t, err)
	require.NotEmpty(t, encryptedMk)

	// 3）对 Key 进行正常解密
	decryptedMk, err := mkLock.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: encryptedMk.Ciphertext,
	})
	require.NoError(t, err)
	require.Equal(t, testKey, []byte(decryptedMk.Plaintext))

	// 解密一个错误的 base64 数据
	decryptedMk, err = mkLock.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: "bad{}base64URLstring[]",
	})
	require.Error(t, err)
	require.Empty(t, decryptedMk)

	// 4）重新构建一个相同的 MasterLock
	mkLock2, err := NewMasterLock(goodPassphrase, sha256.New, salt)
	require.NoError(t, err)

	// 对 Key 进行正常解密
	decryptedMk2, err := mkLock2.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: encryptedMk.Ciphertext,
	})
	require.NoError(t, err)
	require.Equal(t, testKey, []byte(decryptedMk2.Plaintext))

	// 5）重新构建一个不同的 MasterLock (salt is nil)
	mkLock2, err = NewMasterLock(goodPassphrase, sha256.New, nil)
	require.NoError(t, err)

	// 尝试解密
	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: encryptedMk.Ciphertext,
	})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// 6）重新构建一个不同的 MasterLock (different salt)
	salt2 := make([]byte, keySize)
	_, err = rand.Read(salt2)
	require.NoError(t, err)
	mkLock2, err = NewMasterLock(goodPassphrase, sha256.New, salt2)
	require.NoError(t, err)

	// 尝试解密
	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: encryptedMk.Ciphertext,
	})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)

	// 7）重新构建一个 MasterLock（错误的密码）
	mkLock2, err = NewMasterLock("badPassphrase", sha256.New, salt)
	require.NoError(t, err)

	// 尝试解密
	decryptedMk2, err = mkLock2.Decrypt("", &secretlock.DecryptRequest{
		Ciphertext: encryptedMk.Ciphertext,
	})
	require.Error(t, err)
	require.Empty(t, decryptedMk2)
}
