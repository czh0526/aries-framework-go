package didcomm

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
)

type MockOutboundTransport struct {
	ExpectedResponse string
	SendErr          error
	AcceptValue      bool
}

func (m *MockOutboundTransport) Start(prov transport.Provider) error {
	return nil
}

func (m *MockOutboundTransport) Send(data []byte, destination *service.Destination) (string, error) {
	return m.ExpectedResponse, m.SendErr
}

func (m *MockOutboundTransport) AcceptRecipient(strings []string) bool {
	return false
}

func (m *MockOutboundTransport) Accept(s string) bool {
	return m.AcceptValue
}

var _ transport.OutboundTransport = (*MockOutboundTransport)(nil)
