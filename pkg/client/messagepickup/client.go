package messagepickup

import (
	"errors"
	"fmt"
	didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	msgpickupprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	msgpickupprovider "github.com/czh0526/aries-framework-go/provider/messagepickup"
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

func New(ctx msgpickupprovider.ClientProvider) (*Client, error) {
	svc, err := ctx.Service(msgpickupprotocol.MessagePickup)
	if err != nil {
		return nil, fmt.Errorf("failed to create msg pickup service: %w", err)
	}

	msgpickupSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to message pickup service failed")
	}

	return &Client{
		Event:            msgpickupSvc,
		messagepickupSvc: msgpickupSvc,
	}, nil
}
