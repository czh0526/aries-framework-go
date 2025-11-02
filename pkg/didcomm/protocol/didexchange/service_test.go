package didexchange

import (
	"fmt"
	mockstore "github.com/czh0526/aries-framework-go/component/storage/mock"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/czh0526/aries-framework-go/pkg/mock/didcomm/protocol"
	mockroute "github.com/czh0526/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestService_Name(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		prov, err := New(&protocol.MockProvider{
			ServiceMap: map[string]interface{}{
				mediator.Coordination: &mockroute.MockMediatorSvc{},
			},
		})
		require.NoError(t, err)
		require.Equal(t, DIDExchange, prov.Name())
	})
}

func TestServiceNew(t *testing.T) {
	t.Run("test error from open store", func(t *testing.T) {
		_, err := New(
			&protocol.MockProvider{
				StoreProvider: &mockstore.MockStoreProvider{
					ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
				},
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})

	t.Run("test error from opn protocol state store", func(t *testing.T) {
		_, err := New(
			&protocol.MockProvider{
				ProtocolStateStoreProvider: &mockstore.MockStoreProvider{
					ErrOpenStoreHandle: fmt.Errorf("failed to open protocol state store"),
				},
			})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open protocol state store")
	})

	t.Run("test service new error - no router service found", func(t *testing.T) {
		_, err := New(&protocol.MockProvider{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to Router Service failed")
	})
}
