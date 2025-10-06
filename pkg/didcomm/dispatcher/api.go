package dispatcher

import "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

type ProtocolService interface {
	service.Handler
	Accept(msgType string) bool
	Name() string
	Initialize(interface{}) error
}

type MessageService interface {
	service.InboundHandler
	Accept(msgType string, purpose []string) bool
	Name() string
}

type Outbound interface {
	Send(interface{}, string, *service.Destination) error

	SendToDID(msg interface{}, myDID, theirDID string) error

	Forward(interface{}, *service.Destination) error
}
