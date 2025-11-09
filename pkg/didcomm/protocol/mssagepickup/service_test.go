package messagepickup

import (
	"fmt"
	mockstore "github.com/czh0526/aries-framework-go/component/storage/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	mockprovider "github.com/czh0526/aries-framework-go/pkg/mock/provider"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	MYDID    = "sample-my-did"
	THEIRDID = "sample-their-did"
)

func TestServiceNew(t *testing.T) {
	t.Run("test new service - success", func(t *testing.T) {
		svc, err := getService()
		require.NoError(t, err)
		require.Equal(t, MessagePickup, svc.Name())
	})

	t.Run("test new service - store error", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
			},
			ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
			OutboundDispatcherValue:           nil,
			PackagerValue:                     &mockPackager{},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, svc)
	})
}

func TestService_Initialize(t *testing.T) {

}

func getService() (*Service, error) {
	svc, err := New(&mockprovider.Provider{
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		OutboundDispatcherValue:           nil,
		PackagerValue:                     &mockPackager{},
	})

	return svc, err
}

type mockPackager struct {
}

func (m *mockPackager) PackMessage(envelope *transport.Envelope) ([]byte, error) {
	return envelope.Message, nil
}

func (m *mockPackager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	return &transport.Envelope{
		Message: []byte(`{
			"id": "8910",
			"~transport": {
				"return_route": "all"
			}
		}`),
	}, nil
}
