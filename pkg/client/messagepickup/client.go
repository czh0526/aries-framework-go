package messagepickup

import (
	didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	msgpickupprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/messagepickup"
)

type Client struct {
	didcommsvc.Event
	messagepickupSvc protocolService
}

type protocolService interface {
	didcommsvc.DIDComm

	StatusRequest(connID string) (*msgpickupprotocol.Status, error)

	BatchPickup(connID string, size int) (int, error)

	Noop(connID string) error
}
