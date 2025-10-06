package inbound

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/pkg/mock/didcomm/msghandler"
	mockprovider "github.com/czh0526/aries-framework-go/pkg/mock/provider"
	"testing"
)

func TestNewInboundMessageHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		_ = NewInboundMessageHandler(emptyProvider())
	})
}

func emptyProvider() *mockprovider.Provider {
	return &mockprovider.Provider{
		DIDConnectionStoreValue:     &mockDIDStore{},
		MessageServiceProviderValue: &msghandler.MockMsgSvcProvider{},
		InboundMessengerValue:       &mocks.MockMessengerHandler{},
	}
}

type mockDIDResult struct {
	did string
	err error
}

type mockDIDStore struct {
	getDIDErr error
	results   map[string]mockDIDResult
	temps     map[string]mockDIDResult
	countDown uint
}

func (m *mockDIDStore) GetDID(key string) (string, error) {
	if m.getDIDErr != nil {
		return "", m.getDIDErr
	}

	if m.countDown > 0 {
		m.countDown--

		if res, ok := m.temps[key]; ok {
			return res.did, res.err
		}
	}

	if res, ok := m.results[key]; ok {
		return res.did, res.err
	}

	return "", nil
}

func (m *mockDIDStore) SaveDID(string, ...string) error {
	return nil
}

func (m *mockDIDStore) SaveDIDFromDoc(doc *did.Doc) error {
	return nil
}

func (m *mockDIDStore) SaveDIDByResolving(string, ...string) error {
	return nil
}
