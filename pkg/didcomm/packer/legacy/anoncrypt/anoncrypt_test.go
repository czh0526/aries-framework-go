package anoncrypt

import (
	"crypto/ed25519"
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
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"math/rand"
	"testing"
)

func TestEncodingType(t *testing.T) {
	testKMS, store := newKMS(t)
	require.NotEmpty(t, testKMS)

	pack := New(&provider{
		storeProvider: mockStorage.NewCustomMockStoreProvider(store),
		kms:           testKMS,
	})
	require.NotEmpty(t, pack)

	require.Equal(t, encodingType, pack.EncodingType())
}

func TestEncrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)
	require.NotEmpty(t, testingKMS)

	recipientKey := createKey(t, testingKMS)

	t.Run("Success: given keys, generate envelop", func(t *testing.T) {
		pack := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, pack)

		enc, err := pack.Pack("", []byte("Pack my box with five dozen liquor jugs!"),
			[]byte{}, [][]byte{recipientKey})
		require.NoError(t, err)
		require.NotEmpty(t, enc)
	})

	t.Run("Success: with multiple recipients", func(t *testing.T) {
		rec1Key := createKey(t, testingKMS)
		rec2Key := createKey(t, testingKMS)
		rec3Key := createKey(t, testingKMS)
		rec4Key := createKey(t, testingKMS)

		recipientKeys := [][]byte{rec1Key, rec2Key, rec3Key, rec4Key}
		pack := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, pack)

		enc, err := pack.Pack("", []byte("God! a red nugget! a fat egg under a dog!"), []byte{}, recipientKeys)
		require.NoError(t, err)
		require.NotEmpty(t, enc)
	})

	t.Run("Success: pack empty payload using deterministic random source, verify result", func(t *testing.T) {
		senderPub := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		senderPriv := "5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ"

		recipientPub := "CP1eVoFxCguQe1ttDbS3L35ZiJckZ8PZykX1SCDNgEYZ"
		recipientPriv := "5aFcdEMws6ZUL7tWYrJ6DsZvY2GHZYui1jLcYquGr8uHfmyHCs96QU3nRUarH1gVYnMU2i4uUPV5STh2mX7EHpNu"

		kms2, _ := newKMS(t)
		require.NoError(t, persistKey(t, senderPub, senderPriv, kms2))
		require.NoError(t, persistKey(t, recipientPub, recipientPriv, kms2))

		source := rand.NewSource(5937493)
		constRand := rand.New(source)

		pack := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, pack)
		pack.randSource = constRand
		enc, err := pack.Pack("", nil, []byte{}, [][]byte{base58.Decode(recipientPub)})
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRVzV2Ym1OeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklsWXRUMXBaUXpjdFNucEpVVFZGYUhCYWVIb3dTV0ZDTXkxWlZFNXhUbkZ5Y0RaRmVFVXRlbDlNUjFaaldVOVRPRkpaVkZGYVYwcHllVXRRUkU5bU5FNWtTRTVRV0VsQ1JXMUxVbEZoVURscGVGcGlNbUp0VUdnemJuZHlTR0l6VkZFelNWbExZbnBvT0ROdlBTSXNJbWhsWVdSbGNpSTZleUpyYVdRaU9pSkRVREZsVm05R2VFTm5kVkZsTVhSMFJHSlRNMHd6TlZwcFNtTnJXamhRV25scldERlRRMFJPWjBWWldpSjlmVjE5IiwiaXYiOiJpS2RxcUVqc05LaXluLWhrIiwidGFnIjoiR3FVZHVhamVfSHNLS3c3QXJ3dnQ0Zz09In0=" // nolint: lll
		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})

	t.Run("Success: pack payload using deterministic random source for multiple recipients, verify result", func(t *testing.T) { // nolint: lll
		senderPub := "9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw"
		senderPriv := "2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR"
		senderKMS, _ := newKMS(t)
		require.NoError(t, persistKey(t, senderPub, senderPriv, senderKMS))

		rec1Pub := base58.Decode("DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs")
		rec2Pub := base58.Decode("G79vtfWgtBG5J7R2QaBQpZfPUQaAab1QJWedWH7q3VK1")
		rec3Pub := base58.Decode("7snUUwA23DVBmafz9ibmBgwFFCUwzgTzmvcJGepuzjmK")
		rec4Pub := base58.Decode("GSRovbnQy8HRjVjvzGbbfN387EX9NFfLj89C1ScXYfrF")

		source := rand.NewSource(6572692) // constant fixed to ensure constant output
		constRand := rand.New(source)     //nolint:gosec

		pack := newWithKMSAndCrypto(t, senderKMS)
		require.NotEmpty(t, pack)
		pack.randSource = constRand
		enc, err := pack.Pack(
			"",
			[]byte("Sphinx of black quartz, judge my vow!"),
			[]byte{},
			[][]byte{rec1Pub, rec2Pub, rec3Pub, rec4Pub})
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRVzV2Ym1OeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklubFdTWEJ0VTFaSWEyVm9hVXRRWm1GQmRVNW1OMUpyT1c5cmJqTk9WMHhCWjBRM1NVTkNVVVpZVkVnMmN6WXRUbFpRWWtwRE1GQk9OR1ozTkZkZmVWSXpPVVpJTlU1QlJVNW9OMlpOWTBacFdYSmZNbGhCZVhwb1FubG1lRkZ6ZUhCSVh6ZEtkR00yTlVoblBTSXNJbWhsWVdSbGNpSTZleUpyYVdRaU9pSkVSR3MwWVdNeVdrRXhPVkE0Y1ZocWF6aFlZVU5aT1VaNE4xZDNRVzFEZEVWTWEzaGxSRTV4VXpaV2N5SjlmU3g3SW1WdVkzSjVjSFJsWkY5clpYa2lPaUpuZW5ScFpHeFpjWGwwUlRSb2RHczFSbTR3V21KSlRFUnJZbFZZV210WVJqTkZOUzFMTkY5dk1sWlNhREZUZUhkb2JEZHNNbWxTU20xVE1ISmlNREpxWTBaU2QwUkNkMmxxUzFWS1JYbDFTek0yYTBneldXTnRRbVl5UzFGdFVXbE1lR05KUlRoRGEzVkdRVDBpTENKb1pXRmtaWElpT25zaWEybGtJam9pUnpjNWRuUm1WMmQwUWtjMVNqZFNNbEZoUWxGd1dtWlFWVkZoUVdGaU1WRktWMlZrVjBnM2NUTldTekVpZlgwc2V5SmxibU55ZVhCMFpXUmZhMlY1SWpvaVdFdEZWMkZ3YUVzelFTMXBiRVZLTFVwNlVtdFhaRTAwZUVKcFRtTXRXa1ZvVlZwNmRVdFZSVlI2WDFSWlJqRXdSWFZNUXpoZmNHUlVUMUV6VlROSmExVmhMV0ZGUkhGalluZFpSM05VVEVkQlVWVXdZVWh4YlhWbVNHUXRUamxRVTJaVVFuVklWRTVuTFRROUlpd2lhR1ZoWkdWeUlqcDdJbXRwWkNJNklqZHpibFZWZDBFeU0wUldRbTFoWm5vNWFXSnRRbWQzUmtaRFZYZDZaMVI2YlhaalNrZGxjSFY2YW0xTEluMTlMSHNpWlc1amNubHdkR1ZrWDJ0bGVTSTZJblZwTFhFMGJtRmtRVzF5VDFSZmVteE5OWFZHWWpCT1kzRTBaV3h5YVhkQ1gwUk5kRmhsV0U5cGVIazFRblZoYW01S2RHdzVja2RvZDJONlltWmZjbEZ0WTJadUxVMUhXR3BFYlROb1NYUkVjWGQ0YmpoWmVEWnROVUU1T1V4NVdtcHBaemhVTW1OeFoycHJQU0lzSW1obFlXUmxjaUk2ZXlKcmFXUWlPaUpIVTFKdmRtSnVVWGs0U0ZKcVZtcDJla2RpWW1aT016ZzNSVmc1VGtabVRHbzRPVU14VTJOWVdXWnlSaUo5ZlYxOSIsIml2IjoiWW91Q1YtZ2xmUWhQYWw3NSIsImNpcGhlcnRleHQiOiJfY0VDazA0N2NsOGN3RWlLNVJ2S2x2TkQyY05aNW02QU1vb3ZSODJwaTBIS28xZ2ZWQT09IiwidGFnIjoiNmpZR2xreEdaRXp0ME5yQ1lkcFVLUT09In0=" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})
}

func TestDecrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)

	_, recKey, err := testingKMS.CreateAndExportPubKeyBytes(spikms.ED25519Type)
	require.NoError(t, err)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		pack := newWithKMSAndCrypto(t, testingKMS)
		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = pack.Pack("", msgIn, []byte{}, [][]byte{recKey})
		require.NoError(t, err)
		env, err = pack.Unpack(enc)
		require.NoError(t, err)

		require.Equal(t, msgIn, env.Message)
		require.Equal(t, recKey, env.ToKey)
	})

	t.Run("Success: pack then unpack, different packers,", func(t *testing.T) {
		rec1KMS, _ := newKMS(t)
		rec1Key := createKey(t, rec1KMS)

		rec2KMS, _ := newKMS(t)
		rec2Key := createKey(t, rec2KMS)

		rec3KMS, _ := newKMS(t)
		rec3Key := createKey(t, rec3KMS)

		senderPack := newWithKMSAndCrypto(t, testingKMS)
		rec2Pack := newWithKMSAndCrypto(t, rec2KMS)

		msgIn := []byte("junky qoph-flags vext crwd zimb.")

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = senderPack.Pack("", msgIn, []byte{}, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, err)
		env, err = rec2Pack.Unpack(enc)
		require.NoError(t, err)
		require.Equal(t, msgIn, env.Message)
		require.Equal(t, rec2Key, env.ToKey)

		emptyKMS, _ := newKMS(t)
		rec4Pack := newWithKMSAndCrypto(t, emptyKMS)

		_, err = rec4Pack.Unpack(enc)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "no key accessible")
	})
}

type provider struct {
	storeProvider spistorage.Provider
	kms           spikms.KeyManager
	cryptoService spicrypto.Crypto
}

func (p provider) KMS() spikms.KeyManager {
	return p.kms
}

func (p provider) Crypto() spicrypto.Crypto {
	return p.cryptoService
}

func (p provider) StorageProvider() spistorage.Provider {
	return p.storeProvider
}

func (p provider) VDRegistry() vdrapi.Registry {
	return nil
}

var _ packer.Provider = (*provider)(nil)

type kmsProvider struct {
	store             spikms.Store
	secretLockService spisecretlock.Service
}

func (k *kmsProvider) SecretLock() spisecretlock.Service {
	return k.secretLockService
}

func (k *kmsProvider) StorageProvider() spikms.Store {
	return k.store
}

var _ spikms.Provider = (*kmsProvider)(nil)

func newKMS(t *testing.T) (spikms.KeyManager, spistorage.Store) {
	msp := mockStorage.NewMockStoreProvider()
	packerProvider := &provider{storeProvider: msp}

	store, err := packerProvider.StorageProvider().OpenStore("test-kms")
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

func newWithKMSAndCrypto(t *testing.T, km spikms.KeyManager) *Packer {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	return New(&provider{
		kms:           km,
		cryptoService: c,
	})
}

func createKey(t *testing.T, km spikms.KeyManager) []byte {
	_, key, err := km.CreateAndExportPubKeyBytes(spikms.ED25519Type)
	require.NoError(t, err)

	return key
}

func persistKey(t *testing.T, pub, priv string, km spikms.KeyManager) error {
	t.Helper()

	kid, err := jwkkid.CreateKID(base58.Decode(pub), spikms.ED25519Type)
	if err != nil {
		return err
	}

	edPriv := ed25519.PrivateKey(base58.Decode(priv))
	if len(edPriv) == 0 {
		return fmt.Errorf("error converting ed25519 private key")
	}

	k1, _, err := km.ImportPrivateKey(edPriv, spikms.ED25519Type, spikms.WithKeyID(kid))
	require.NoError(t, err)
	require.Equal(t, kid, k1)

	return nil
}
