package outbound

import (
	mockkms "github.com/czh0526/aries-framework-go/component/kmscrypto/mock/kms"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	mockstorage "github.com/czh0526/aries-framework-go/component/storageutil/mock/storage"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	vdrmock "github.com/czh0526/aries-framework-go/component/vdr/mock"
	"github.com/czh0526/aries-framework-go/pkg/common/model"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockdidcomm "github.com/czh0526/aries-framework-go/pkg/mock/didcomm"
	mockpackager "github.com/czh0526/aries-framework-go/pkg/mock/didcomm/packager"
	mockdiddoc "github.com/czh0526/aries-framework-go/pkg/mock/diddoc"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"
	"testing"
)

const testDID = "did:test:abc"

func TestOutboundDispatcher_Send(t *testing.T) {
	t.Run("V1 test success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstorage.NewMockStoreProvider(),
			protoStorageProvider:    mockstorage.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeV1PlaintextPayload},
		})
		require.NoError(t, err)

		err = o.Send("data", mockdiddoc.MockDIDKey(t),
			&service.Destination{
				ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("url"),
			})
		require.NoError(t, err)
	})

	t.Run("V2 test success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstorage.NewMockStoreProvider(),
			protoStorageProvider:    mockstorage.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		fromDIDDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alice")
		toDIDDoc := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "bob")

		err = o.Send("data", fromDIDDoc.KeyAgreement[0].VerificationMethod.ID,
			&service.Destination{
				RecipientKeys: []string{toDIDDoc.KeyAgreement[0].VerificationMethod.ID},
				ServiceEndpoint: model.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{
					{
						URI:    "url",
						Accept: []string{transport.MediaTypeDIDCommV2Profile},
					},
				}),
			})
		require.NoError(t, err)
	})

	t.Run("test send with forward message - success", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue:           &mockpackager.Packager{PackValue: createPackedMsgForForward(t)},
			outboundTransportsValue: []transport.OutboundTransport{&mockdidcomm.MockOutboundTransport{AcceptValue: true}},
			storageProvider:         mockstorage.NewMockStoreProvider(),
			protoStorageProvider:    mockstorage.NewMockStoreProvider(),
			mediaTypeProfiles:       []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		err = o.Send("data", mockdiddoc.MockDIDKey(t),
			&service.Destination{
				ServiceEndpoint: endpoint.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{
					{
						URI:         "url",
						RoutingKeys: []string{"xyz"},
					},
				}),
				RecipientKeys: []string{"abc"},
			})
		require.NoError(t, err)
	})
}

func TestOutboundDispatcher_SendToDID(t *testing.T) {
	mockDoc := mockdiddoc.GetMockDIDDoc(t, false)

	t.Run("success with existing connection record", func(t *testing.T) {
		o, err := NewOutbound(&mockProvider{
			packagerValue: &mockpackager.Packager{
				PackValue: createPackedMsgForForward(t),
			},
			vdr: &vdrmock.VDRegistry{
				ResolveValue: mockDoc,
			},
			outboundTransportsValue: []transport.OutboundTransport{
				&mockdidcomm.MockOutboundTransport{AcceptValue: true},
			},
			storageProvider:      mockstorage.NewMockStoreProvider(),
			protoStorageProvider: mockstorage.NewMockStoreProvider(),
			mediaTypeProfiles:    []string{transport.MediaTypeDIDCommV2Profile},
		})
		require.NoError(t, err)

		o.connections = &mockConnectionLookup{
			getConnectionByDIDsVal: "mock1",
			getConnectionRecordVal: &connection.Record{},
		}

		err = o.SendToDID(service.DIDCommMsgMap{
			"@id":   "123",
			"@type": "abc",
		}, testDID, "")
		require.NoError(t, err)
	})
}

func createPackedMsgForForward(_ *testing.T) []byte {
	return []byte("")
}

type mockProvider struct {
	packagerValue           transport.Packager
	outboundTransportsValue []transport.OutboundTransport
	transportReturnRoute    string
	vdr                     vdrapi.Registry
	kms                     spikms.KeyManager
	storageProvider         spistorage.Provider
	protoStorageProvider    spistorage.Provider
	mediaTypeProfiles       []string
	keyAgreementType        spikms.KeyType
	didRotator              middleware.DIDCommMessageMiddleware
}

func (m *mockProvider) Packager() transport.Packager {
	return m.packagerValue
}

func (m *mockProvider) OutboundTransports() []transport.OutboundTransport {
	return m.outboundTransportsValue
}

func (m *mockProvider) TransportReturnRoute() string {
	return m.transportReturnRoute
}

func (m *mockProvider) VDRegistry() vdrapi.Registry {
	return m.vdr
}

func (m *mockProvider) KMS() spikms.KeyManager {
	if m.kms != nil {
		return m.kms
	}

	return &mockkms.KeyManager{}
}

func (m *mockProvider) KeyAgreementType() spikms.KeyType {
	return m.keyAgreementType
}

func (m *mockProvider) ProtocolStateStorageProvider() spistorage.Provider {
	return m.protoStorageProvider
}

func (m *mockProvider) StorageProvider() spistorage.Provider {
	return m.storageProvider
}

func (m *mockProvider) MediaTypeProfiles() []string {
	return m.mediaTypeProfiles
}

func (m *mockProvider) DIDRotator() *middleware.DIDCommMessageMiddleware {
	return &m.didRotator
}

var _ provider = (*mockProvider)(nil)

type mockConnectionLookup struct {
	getConnectionByDIDsVal string
	getConnectionByDIDsErr error
	getConnectionRecordVal *connection.Record
	getConnectionRecordErr error
	saveConnectionErr      error
}

func (m mockConnectionLookup) GetConnectionIDByDIDs(myDID, theirDID string) (string, error) {
	return m.getConnectionByDIDsVal, m.getConnectionByDIDsErr
}

func (m mockConnectionLookup) GetConnectionRecord(s string) (*connection.Record, error) {
	return m.getConnectionRecordVal, m.getConnectionRecordErr
}

func (m mockConnectionLookup) GetConnectionRecordByDIDs(myDID, theirDID string) (*connection.Record, error) {
	if m.getConnectionByDIDsErr != nil {
		return nil, m.getConnectionByDIDsErr
	}

	return m.getConnectionRecordVal, m.getConnectionRecordErr
}

func (m mockConnectionLookup) SaveConnectionRecord(record *connection.Record) error {
	return m.saveConnectionErr
}

var _ connectionRecorder = (*mockConnectionLookup)(nil)
