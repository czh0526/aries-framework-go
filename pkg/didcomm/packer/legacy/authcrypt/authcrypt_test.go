package authcrypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	mockStorage "github.com/czh0526/aries-framework-go/component/storageutil/mock/storage"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	insecurerand "math/rand"
	"testing"
)

type provider struct {
	storeProvider spistorage.Provider
	kms           spikms.KeyManager
	secretLock    spisecretlock.Service
	cryptoService spicrypto.Crypto
}

func (p *provider) KMS() spikms.KeyManager {
	return p.kms
}

func (p *provider) VDRegistry() vdrapi.Registry {
	return nil
}

func (p *provider) StorageProvider() spistorage.Provider {
	return p.storeProvider
}

func (p *provider) Crypto() spicrypto.Crypto {
	return p.cryptoService
}

type kmsProvider struct {
	store             spikms.Store
	secretLockService spisecretlock.Service
}

func (k *kmsProvider) StorageProvider() spikms.Store {
	return k.store
}

func (k *kmsProvider) SecretLock() spisecretlock.Service {
	return k.secretLockService
}

var _ spikms.Provider = (*kmsProvider)(nil)

func newKMS(t *testing.T) (spikms.KeyManager, spistorage.Store) {
	msp := mockStorage.NewMockStoreProvider()

	store, err := msp.OpenStore("test-kms")
	require.NoError(t, err)

	kmsStore, err := kms.NewAriesProviderWrapper(msp)
	require.NoError(t, err)

	kmsProv := &kmsProvider{
		store:             kmsStore,
		secretLockService: &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS, store
}

func TestEncodingType(t *testing.T) {
	// 构建 kms 和 store
	testKMS, store := newKMS(t)
	require.NotEmpty(t, testKMS)

	packer := New(&provider{
		storeProvider: mockStorage.NewCustomMockStoreProvider(store),
		kms:           testKMS,
	})
	require.NotEmpty(t, packer)

	require.Equal(t, encodingType, packer.EncodingType())
}

func TestEncrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)
	senderKey := createKey(t, testingKMS)
	recipientKey := createKey(t, testingKMS)

	t.Run("Success test case: given keys, generate envelope", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, packer)

		enc, e := packer.Pack("", []byte("Pack my box with five dozen liquor jugs!"),
			senderKey, [][]byte{recipientKey})
		require.NoError(t, e)
		require.NotEmpty(t, enc)
	})

	t.Run("Success test case: given keys, generate envelope with multiple recipients", func(t *testing.T) {
		senderKey1 := createKey(t, testingKMS)
		rec1Key := createKey(t, testingKMS)
		rec2Key := createKey(t, testingKMS)
		rec3Key := createKey(t, testingKMS)
		rec4Key := createKey(t, testingKMS)

		recipientKeys := [][]byte{rec1Key, rec2Key, rec3Key, rec4Key}
		packer := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, packer)

		enc, err := packer.Pack("", []byte("God! a red nugget! A fat egg under a dog!"), senderKey1, recipientKeys)
		require.NoError(t, err)
		require.NotEmpty(t, enc)
	})

	t.Run("Pack empty payload using deterministic random source, verify result", func(t *testing.T) {
		senderPub := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		senderPriv := "5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ"

		recipientPub := "CP1eVoFxCguQe1ttDbS3L35ZiJckZ8PZykX1SCDNgEYZ"
		recipientPriv := "5aFcdEMws6ZUL7tWYrJ6DsZvY2GHZYui1jLcYquGr8uHfmyHCs96QU3nRUarH1gVYnMU2i4uUPV5STh2mX7EHpNu"

		// 构建 KMS
		kms2, _ := newKMS(t)
		// 保存发送者、接收者的密钥
		require.NoError(t, persistKey(t, senderPub, senderPriv, kms2))
		require.NoError(t, persistKey(t, recipientPub, recipientPriv, kms2))

		source := insecurerand.NewSource(5937493)
		constRand := insecurerand.New(source)

		// 构建 Packer
		packer := newWithKMSAndCrypto(t, kms2)
		require.NotEmpty(t, packer)
		packer.randSource = constRand

		// 测试 Packer
		enc, err := packer.Pack("", nil, base58.Decode(senderPub), [][]byte{base58.Decode(recipientPub)})
		require.NoError(t, err)

		// 校验结果
		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRWFYwYUdOeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklqSmlVRFl0VnpaWldXZHpjMlZpVWxOaU0xWlljV0pMTlZWa2FpMDNOSGxGTTFFdFZXaHpjMUF3Vm1aclRHNVhiMFk0WjBSNVVHRkJlREI0VWtGM2NIVWlMQ0pvWldGa1pYSWlPbnNpYTJsa0lqb2lRMUF4WlZadlJuaERaM1ZSWlRGMGRFUmlVek5NTXpWYWFVcGphMW80VUZwNWExZ3hVME5FVG1kRldWb2lMQ0p6Wlc1a1pYSWlPaUpHYzIwMU5WOUNTRkJzVkdsd2RUQlFabEZDY2t0SmRuZ3lTRGw0VTBndFVtbHpXRzgxVVdoemQwTTNjR28yTm5BMVNtOUpVVjlIT1hGdFRrVldNRzVGVG5sTVIwczFlVVZuUzJoeU5ESTBVMnBJYkRWSmQzQnljRnBqYUdGNVprNWtWa2xJTFdKNlprRnhjbXhDWTIxUVZEWkpkR2R4Y3poclRHczlJaXdpYVhZaU9pSm1OV3BVT0VKS2FHeEVZbTQwUWxvMFNGcGZSSEExTkU5TGQyWmxRV1JSTWlKOWZWMTkiLCJpdiI6ImlLZHFxRWpzTktpeW4taGsiLCJ0YWciOiIySm5SbF9iXzM2QS1WaWFKNzNCb1FBPT0ifQ==" // nolint: lll
		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})
}

func TestEncryptComponents(t *testing.T) {
	senderPub := "9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw"
	senderPriv := "2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR"
	rec1Pub := "DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs"

	testKMS, _ := newKMS(t)
	require.NoError(t, persistKey(t, senderPub, senderPriv, testKMS))

	packer := newWithKMSAndCrypto(t, testKMS)

	t.Run("Success: 4 reads necessary for pack", func(t *testing.T) {
		packer.randSource = rand.Reader

		_, err := packer.Pack("",
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			base58.Decode(senderPub),
			[][]byte{base58.Decode(rec1Pub)},
		)
		require.NoError(t, err)
	})

	packer2 := newWithKMSAndCrypto(t, testKMS)

	t.Run("Failure: generate recipient header with bad sender key", func(t *testing.T) {
		_, err := packer2.buildRecipient(&[32]byte{}, []byte(""), base58.Decode(rec1Pub))
		require.EqualError(t, err, "buildRecipient: failed to create KID for sender key: createKID: empty key")
	})

	t.Run("Failure: generate recipient header with bad recipient key", func(t *testing.T) {
		_, err := packer2.buildRecipient(&[32]byte{}, base58.Decode(senderPub), base58.Decode("AAAA"))
		require.EqualError(t, err, "buildRecipient: failed to convert public Ed25519 to Curve25519: 3-byte key size is invalid")
	})
}

func TestDecrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)
	_, senderKey, err := testingKMS.CreateAndExportPubKeyBytes(spikms.ED25519Type)
	require.NoError(t, err)

	_, recKey, err := testingKMS.CreateAndExportPubKeyBytes(spikms.ED25519Type)
	require.NoError(t, err)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, testingKMS)
		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = packer.Pack("", msgIn, senderKey, [][]byte{recKey})
		require.NoError(t, err)
		env, err := packer.Unpack(enc)
		require.NoError(t, err)

		require.ElementsMatch(t, msgIn, env.Message)
		require.Equal(t, senderKey, env.FromKey)
		require.Equal(t, recKey, env.ToKey)
	})

	t.Run("Success: pack then unpack, different packers, including fail recipient who wasn't sent the message", func(t *testing.T) {
		rec1KMS, _ := newKMS(t)
		rec1PubKeyBytes := createKey(t, rec1KMS)

		rec2KMS, _ := newKMS(t)
		rec2PubKeyBytes := createKey(t, rec2KMS)

		rec3KMS, _ := newKMS(t)
		rec3PubKeyBytes := createKey(t, rec3KMS)

		senderPacker := newWithKMSAndCrypto(t, testingKMS)
		rec2Packer := newWithKMSAndCrypto(t, rec2KMS)

		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = senderPacker.Pack("", msgIn, senderKey, [][]byte{rec1PubKeyBytes, rec2PubKeyBytes, rec3PubKeyBytes})
		require.NoError(t, err)

		env, err = rec2Packer.Unpack(enc)
		require.NoError(t, err)

		require.ElementsMatch(t, msgIn, env.Message)
		require.Equal(t, senderKey, env.FromKey)
		require.Equal(t, rec2PubKeyBytes, env.ToKey)

		emptyKMS, _ := newKMS(t)
		rec4Packer := newWithKMSAndCrypto(t, emptyKMS)

		_, err = rec4Packer.Unpack(enc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no key accessible")
	})
}

func createKey(t *testing.T, km spikms.KeyManager) []byte {
	_, pubKeyBytes, err := km.CreateAndExportPubKeyBytes(spikms.ED25519Type)
	require.NoError(t, err)

	return pubKeyBytes
}

func persistKey(t *testing.T, pub, priv string, km spikms.KeyManager) error {
	t.Helper()

	kid, err := jwkkid.CreateKID(base58.Decode(pub), spikms.ED25519Type)
	if err != nil {
		return err
	}

	edPriv := ed25519.PrivateKey(base58.Decode(priv))
	if len(edPriv) == 0 {
		return fmt.Errorf("invalid ed25519 private key")
	}

	k1, _, err := km.ImportPrivateKey(edPriv, spikms.ED25519Type, spikms.WithKeyID(kid))
	require.NoError(t, err)
	require.Equal(t, kid, k1)

	return nil
}

func newWithKMSAndCrypto(t *testing.T, km spikms.KeyManager) *Packer {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	return New(&provider{
		kms:           km,
		cryptoService: c,
	})
}
