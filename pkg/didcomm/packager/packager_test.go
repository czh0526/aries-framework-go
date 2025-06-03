package packager

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/models/did"
	mockstorage "github.com/czh0526/aries-framework-go/component/storage/mock"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/czh0526/aries-framework-go/spi/secretlock"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"github.com/stretchr/testify/require"
	"testing"
)

const localKeyURI = "local-lock://test/key-uri/"

func TestNewPackagerMissingPrimaryPacker(t *testing.T) {
	mockedProviders := &mockProvider{}

	_, err := New(mockedProviders)
	require.EqualError(t, err, "need primary packer to initialize packager")
}

func TestBaseKMSInPackager_UnpackMessage(t *testing.T) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	t.Run("test Pack/Unpack success", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI, newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		tests := []struct {
			name    string
			keyType spikms.KeyType
		}{
			{
				name:    "Pack/Unpack success with P-256 ECDH HW keys",
				keyType: spikms.NISTP256ECDHKWType,
			},
			{
				name:    "Pack/Unpack success with P-384 ECDH KW keys",
				keyType: spikms.NISTP384ECDHKWType,
			},
			{
				name:    "Pack/Unpack success with P-521 ECDH KW keys",
				keyType: spikms.NISTP521ECDHKWType,
			},
			{
				name:    "Pack/Unpack success with X25519 ECDH KW keys",
				keyType: spikms.X25519ECDHKWType,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				packUnpackSuccess(tt.keyType, customKMS, cryptoSvc, t)
			})
		}
	})
}

func packUnpackSuccess(keyType spikms.KeyType, customKMS spikms.KeyManager, cryptoSvc spicrypto.Crypto, t *testing.T) {
	resolveDIDFunc, fromDIDKey, toDIDKey, fromDID, toDID := newDIDsAndDIDDocResolverFunc(
		customKMS, keyType, t)

}

type resolverFunc func(didID string, opts ...spivdr.DIDMethodOption)

func newDIDsAndDIDDocResolverFunc(customKMS spikms.KeyManager, keyType spikms.KeyType, t *testing.T) (
	resolverFunc, string, string, *did.Doc, *did.Doc) {
	t.Helper()

	_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(keyType)

}

func newMockKMSProvider(provider *mockstorage.MockStoreProvider, t *testing.T) spikms.Provider {
	storeProvider, err := kms.NewAriesProviderWrapper(provider)
	require.NoError(t, err)

	return &kmsProvider{
		kmsStore:          storeProvider,
		secretLockService: &noop.NoLock{},
	}
}

type kmsProvider struct {
	kmsStore          spikms.Store
	secretLockService secretlock.Service
}

type mockProvider struct {
	packers       []packer.Packer
	primaryPacker packer.Packer
	vdr           vdrapi.Registry
}

func (m *mockProvider) PrimaryPacker() packer.Packer {
	return m.primaryPacker
}

func (m *mockProvider) VDRegistry() vdrapi.Registry {
	return m.vdr
}

func (m *mockProvider) Packers() []packer.Packer {
	return m.packers
}
