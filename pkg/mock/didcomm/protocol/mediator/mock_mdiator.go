package mediator

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/google/uuid"
)

type MockMediatorSvc struct {
	service.Action
	service.Message
	ProtocolName       string
	HandleFunc         func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc         func(msgType string) bool
	RegisterFunc       func(connectionID string, options ...mediator.ClientOption) error
	AddKeyErr          error
	AddKeyFunc         func(string) error
	ConfigErr          error
	RoutingKeys        []string
	RouterEndpoint     string
	GetConnectionsErr  error
	Connections        []string
}

func (m *MockMediatorSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

func (m *MockMediatorSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "route"
}

func (m *MockMediatorSvc) Initialize(i interface{}) error {
	return nil
}

func (m *MockMediatorSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return "", nil
}

func (m *MockMediatorSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

func (m *MockMediatorSvc) AddKey(connID, recKey string) error {
	if m.AddKeyErr != nil {
		return m.AddKeyErr
	}

	if m.AddKeyFunc != nil {
		return m.AddKeyFunc(recKey)
	}

	return nil
}

func (m *MockMediatorSvc) Config(connID string) (*mediator.Config, error) {
	if m.ConfigErr != nil {
		return nil, m.ConfigErr
	}
	if m.RouterEndpoint == "" || m.RoutingKeys == nil {
		return nil, mediator.ErrRouterNotRegistered
	}

	return mediator.NewConfig(m.RouterEndpoint, m.RoutingKeys), nil
}

func (m *MockMediatorSvc) GetConnections(options ...mediator.ConnectionOption) ([]string, error) {
	if m.GetConnectionsErr != nil {
		return nil, m.GetConnectionsErr
	}

	return m.Connections, nil
}

var _ service.Handler = (*MockMediatorSvc)(nil)
var _ dispatcher.ProtocolService = (*MockMediatorSvc)(nil)
var _ mediator.ProtocolService = (*MockMediatorSvc)(nil)
