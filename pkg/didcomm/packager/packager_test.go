package packager

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/models/did"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	mockstorage "github.com/czh0526/aries-framework-go/component/storage/mock"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	comp_mockvdr "github.com/czh0526/aries-framework-go/component/vdr/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer/authcrypt"
	legacy "github.com/czh0526/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockdiddoc "github.com/czh0526/aries-framework-go/pkg/mock/diddoc"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
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
			//{
			//	name:    "Pack/Unpack success with P-384 ECDH KW keys",
			//	keyType: spikms.NISTP384ECDHKWType,
			//},
			//{
			//	name:    "Pack/Unpack success with P-521 ECDH KW keys",
			//	keyType: spikms.NISTP521ECDHKWType,
			//},
			//{
			//	name:    "Pack/Unpack success with X25519 ECDH KW keys",
			//	keyType: spikms.X25519ECDHKWType,
			//},
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

	mockedProviders := &mockProvider{
		kms:    customKMS,
		crypto: cryptoSvc,
		vdr: &comp_mockvdr.VDRegistry{
			ResolveFunc: resolveDIDFunc,
		},
	}

	testPacker, err := authcrypt.New(mockedProviders, jose.A256CBCHS512)
	require.NoError(t, err)

	mockedProviders.primaryPacker = testPacker

	legacyPacker := legacy.New(mockedProviders)
	mockedProviders.packers = []packer.Packer{testPacker, legacyPacker}

	packager, err := New(mockedProviders)
	require.NoError(t, err)

	_, fromKeyED25519, err := customKMS.CreateAndExportPubKeyBytes(spikms.ED25519)
	require.NoError(t, err)

	fromDIDKeyED25519, _ := fingerprint.CreateDIDKey(fromKeyED25519)

	_, toKeyEd25519, err := customKMS.CreateAndExportPubKeyBytes(spikms.ED25519)
	require.NoError(t, err)

	toLegacyDIDKey, _ := fingerprint.CreateDIDKey(toKeyEd25519)

	tests := []struct {
		name              string
		mediaType         string
		isKeyAgreementKey bool
	}{
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeRFC0019EncryptedEnvelope),
			mediaType: transport.MediaTypeRFC0019EncryptedEnvelope,
		},
		{
			name:      fmt.Sprintf("success using mdiaType %s", transport.MediaTypeV1PlaintextPayload),
			mediaType: transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeV1EncryptedEnvelope),
			mediaType: transport.MediaTypeV1EncryptedEnvelope,
		},
		{
			name:      fmt.Sprintf("success using mdiaType %s", transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload),
			mediaType: transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
		},
		{
			name:      fmt.Sprintf("success using mdiaType %s", transport.MediaTypeV2PlaintextPayload),
			mediaType: transport.MediaTypeV2EncryptedEnvelope,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeAIP2RFC0019Profile),
			mediaType: transport.MediaTypeAIP2RFC0019Profile,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeProfileDIDCommAIP1),
			mediaType: transport.MediaTypeProfileDIDCommAIP1,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeAIP2RFC0587Profile),
			mediaType: transport.MediaTypeAIP2RFC0587Profile,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeDIDCommV2Profile),
			mediaType: transport.MediaTypeDIDCommV2Profile,
		},
		{
			name: fmt.Sprintf("success using mediaType %s with KeyAgreement",
				transport.MediaTypeAIP2RFC0587Profile),
			mediaType:         transport.MediaTypeAIP2RFC0587Profile,
			isKeyAgreementKey: true,
		},
		{
			name:              fmt.Sprintf("success using mediaType %s with KeyAgreement", transport.MediaTypeDIDCommV2Profile),
			mediaType:         transport.MediaTypeDIDCommV2Profile,
			isKeyAgreementKey: true,
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			var (
				fromKIDPack []byte
				toKIDsPack  []string
			)

			switch tc.mediaType {
			case transport.MediaTypeRFC0019EncryptedEnvelope, transport.MediaTypeAIP2RFC0019Profile,
				transport.MediaTypeProfileDIDCommAIP1:
				fromKIDPack = []byte(fromDIDKeyED25519)
				toKIDsPack = []string{toLegacyDIDKey}

			case transport.MediaTypeV1EncryptedEnvelope, transport.MediaTypeV1PlaintextPayload,
				transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2PlaintextPayload,
				transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeAIP2RFC0587Profile,
				transport.MediaTypeDIDCommV2Profile:
				if tc.isKeyAgreementKey {
					fromKIDPack = []byte(fromDID.KeyAgreement[0].VerificationMethod.ID)
					toKIDsPack = []string{toDID.KeyAgreement[0].VerificationMethod.ID}
				} else {
					fromKIDPack = []byte(fromDIDKey)
					toKIDsPack = []string{toDIDKey}
				}
			}

			packMsg, err := packager.PackMessage(&transport.Envelope{
				MediaTypeProfile: tc.mediaType,
				Message:          []byte("msg"),
				FromKey:          fromKIDPack,
				ToKeys:           toKIDsPack,
			})
			require.NoError(t, err)

			unpackedMsg, err := packager.UnpackMessage(packMsg)
			require.NoError(t, err)
			require.Equal(t, unpackedMsg.Message, []byte("msg"))
		})
	}
}

type resolverFunc func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)

func newDIDsAndDIDDocResolverFunc(customKMS spikms.KeyManager, keyType spikms.KeyType, t *testing.T) (
	resolverFunc, string, string, *did.Doc, *did.Doc) {
	t.Helper()

	// sender
	_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	fromDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(fromKey, keyType)
	require.NoError(t, err)

	fromJWK, err := jwkkid.BuildJWK(fromKey, keyType)
	require.NoError(t, err)

	vmKeyType := "JsonWebKey2020"
	if keyType == spikms.X25519ECDHKWType {
		vmKeyType = "X25519KeyAgreementKey2019"
	}

	fromDID := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alicedid")
	fromKA, err := didmodel.NewVerificationMethodFromJWK(
		fromDID.KeyAgreement[0].VerificationMethod.ID, vmKeyType, fromDID.ID, fromJWK)
	require.NoError(t, err)

	fromDID.KeyAgreement = []did.Verification{
		{
			VerificationMethod: *fromKA,
		},
	}

	// receiver
	_, toKey, err := customKMS.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	toDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(toKey, keyType)
	require.NoError(t, err)

	toJWK, err := jwkkid.BuildJWK(toKey, keyType)
	require.NoError(t, err)

	toDID := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "bobdid")
	toKA, err := did.NewVerificationMethodFromJWK(
		toDID.KeyAgreement[0].VerificationMethod.ID, vmKeyType, toDID.ID, toJWK)
	require.NoError(t, err)

	toDID.KeyAgreement = []did.Verification{
		{
			VerificationMethod: *toKA,
		},
	}

	resolveDID := func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
		switch didID {
		case toDID.ID:
			return &did.DocResolution{
				DIDDocument: toDID,
			}, nil

		case fromDID.ID:
			return &did.DocResolution{
				DIDDocument: fromDID,
			}, nil

		default:
			return nil, fmt.Errorf("did not found: %s", didID)
		}
	}

	return resolveDID, fromDIDKey, toDIDKey, fromDID, toDID
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
	secretLockService spisecretlock.Service
}

func (k kmsProvider) StorageProvider() spikms.Store {
	return k.kmsStore
}

func (k kmsProvider) SecretLock() spisecretlock.Service {
	return k.secretLockService
}

type mockProvider struct {
	storage       spistorage.Provider
	kms           spikms.KeyManager
	secretLock    spisecretlock.Service
	crypto        spicrypto.Crypto
	packers       []packer.Packer
	primaryPacker packer.Packer
	vdr           vdrapi.Registry
}

func (m *mockProvider) KMS() spikms.KeyManager {
	return m.kms
}

func (m *mockProvider) Crypto() spicrypto.Crypto {
	return m.crypto
}

func (m *mockProvider) StorageProvider() spistorage.Provider {
	return m.storage
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
