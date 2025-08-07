package localkms

import (
	"crypto/rand"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	"github.com/stretchr/testify/require"
	"testing"
)

type testProvider struct {
	storeProvider      spikms.Store
	secretLockProvider spisecretlock.Service
}

func (p *testProvider) StorageProvider() spikms.Store {
	return p.storeProvider
}

func (p *testProvider) SecretLock() spisecretlock.Service {
	return p.secretLockProvider
}

func newKMS(t *testing.T) *LocalKMS {

	testStore := newInMemoryKMSStore()
	p := testProvider{
		storeProvider:      testStore,
		secretLockProvider: &noop.NoLock{},
	}

	mainLockURI := "local-lock://test/uri/"
	localKms, err := New(mainLockURI, &p)
	require.NoError(t, err)

	return localKms
}

func TestNewCryptoNox(t *testing.T) {
	k := newKMS(t)
	b, err := NewCryptoBox(k)
	require.NoError(t, err)
	require.Equal(t, b.km, k)

	_, err = NewCryptoBox(spikms.KeyManager(nil))
	require.Error(t, err, "cannot use parameter argument as KMS")
}

func TestBoxSeal(t *testing.T) {
	// 构建一个 KMS
	k := newKMS(t)

	// 构建 CryptoBox
	b, err := NewCryptoBox(k)
	require.NoError(t, err)

	// 向 KMS 中填充一个公钥
	_, rec1PubKey, err := k.CreateAndExportPubKeyBytes(spikms.ED25519)
	require.NoError(t, err)

	rec1EncPubKey, err := cryptoutil.PublicEd25519toCurve25519(rec1PubKey)
	require.NoError(t, err)

	t.Run("Seal a message with sodiumBoxSeal and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit")

		enc, err := b.Seal(msg, rec1EncPubKey, rand.Reader)
		require.NoError(t, err)

		dec, err := b.SealOpen(enc, rec1PubKey)
		require.NoError(t, err)

		require.Equal(t, msg, dec)
	})
}

func TestBoxEasy(t *testing.T) {
	// 构建一个 KMS
	k := newKMS(t)

	// 构建 CryptoBox
	b, err := NewCryptoBox(k)
	require.NoError(t, err)

	// 接收者的密钥对
	_, recipientPubKey, err := k.CreateAndExportPubKeyBytes(spikms.ED25519)
	require.NoError(t, err)

	recipientEncPubKey, err := cryptoutil.PublicEd25519toCurve25519(recipientPubKey)
	require.NoError(t, err)

	// 发送者的密钥对
	senderKID, senderPubKey, err := k.CreateAndExportPubKeyBytes(spikms.ED25519)
	require.NoError(t, err)

	senderEncPubKey, err := cryptoutil.PublicEd25519toCurve25519(senderPubKey)
	require.NoError(t, err)

	t.Run("Seal a message with sodiumBoxSealOpen, and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		nonce := []byte("abcdefghijklmnopqrstuvwx")
		msg := []byte("this is a test message")

		enc, err := b.Easy(msg, nonce, recipientEncPubKey, senderKID)
		require.NoError(t, err)

		plaintext, err := b.EasyOpen(enc, nonce, senderEncPubKey, recipientPubKey)
		require.NoError(t, err)
		require.EqualValues(t, msg, plaintext)
	})
}
