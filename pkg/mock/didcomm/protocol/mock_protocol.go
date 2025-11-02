package protocol

import (
	mockcrypto "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/crypto"
	mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	mockstore "github.com/czh0526/aries-framework-go/component/storage/mock"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	mockvdr "github.com/czh0526/aries-framework-go/component/vdr/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockdispatcher "github.com/czh0526/aries-framework-go/pkg/mock/didcomm/dispatcher"
	mockservice "github.com/czh0526/aries-framework-go/pkg/mock/didcomm/service"
	"github.com/czh0526/aries-framework-go/pkg/store/did"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

type MockProvider struct {
	StoreProvider                spistorage.Provider
	ProtocolStateStoreProvider   spistorage.Provider
	KMSStore                     spikms.Store
	CustomVDR                    vdrapi.Registry
	CustomOutbound               *mockdispatcher.MockOutbound
	CustomMessenger              *mockservice.MockMessenger
	CustomPackager               transport.Packager
	CustomKMS                    spikms.KeyManager
	CustomLock                   spisecretlock.Service
	CustomCrypto                 *mockcrypto.Crypto
	ServiceErr                   error
	ServiceMap                   map[string]interface{}
	InboundMsgHandler            transport.InboundMessageHandler
	InboundDIDCommMsgHandlerFunc func() service.InboundHandler
	KeyTypeValue                 spikms.KeyType
	KeyAgreementTypeValue        spikms.KeyType
	mediaTypeProfilesValue       []string
	MsgTypeServicesTargets       []dispatcher.MessageTypeTarget
	AllProtocolServices          []dispatcher.ProtocolService
	RouterEndpointValue          string
}

func (m *MockProvider) OutboundDispatcher() dispatcher.Outbound {
	if m.CustomOutbound != nil {
		return m.CustomOutbound
	}
	return &mockdispatcher.MockOutbound{}
}

func (m *MockProvider) StorageProvider() spistorage.Provider {
	if m.StoreProvider != nil {
		return m.StoreProvider
	}
	return mockstore.NewMockStoreProvider()
}

func (m *MockProvider) ProtocolStateStorageProvider() spistorage.Provider {
	if m.ProtocolStateStoreProvider != nil {
		return m.ProtocolStateStoreProvider
	}

	return mockstore.NewMockStoreProvider()
}

func (m *MockProvider) DIDConnectionStore() did.ConnectionStore {
	return &mockConnectionStore{}
}

func (m *MockProvider) Crypto() spicrypto.Crypto {
	return &mockcrypto.Crypto{}
}

func (m *MockProvider) KMS() spikms.KeyManager {
	if m.CustomKMS != nil {
		return m.CustomKMS
	}
	return &mockkms.KeyManager{}
}

func (m *MockProvider) VDRegistry() vdrapi.Registry {
	if m.CustomVDR != nil {
		return m.CustomVDR
	}

	return &mockvdr.VDRegistry{}
}

func (m *MockProvider) Service(id string) (interface{}, error) {
	if m.ServiceErr != nil {
		return nil, m.ServiceErr
	}

	return m.ServiceMap[id], nil
}

func (m *MockProvider) KeyType() spikms.KeyType {
	return m.KeyTypeValue
}

func (m *MockProvider) KeyAgreementType() spikms.KeyType {
	return m.KeyAgreementTypeValue
}

func (m MockProvider) MediaTypeProfiles() []string {
	return m.mediaTypeProfilesValue
}

type mockConnectionStore struct {
}

func (m mockConnectionStore) GetDID(key string) (string, error) {
	return "", nil
}

func (m mockConnectionStore) SaveDID(did string, keys ...string) error {
	return nil
}

func (m mockConnectionStore) SaveDIDFromDoc(doc *didmodel.Doc) error {
	return nil
}

func (m mockConnectionStore) SaveDIDByResolving(did string, keys ...string) error {
	return nil
}
