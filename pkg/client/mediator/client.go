package mediator

import (
	"errors"
	didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	medprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mediator"
	medprovider "github.com/czh0526/aries-framework-go/provider/mediator"
	"time"
)

type Client struct {
	didcommsvc.Event
	routeSvc protocolService
	options  []medprotocol.ClientOption
}

type protocolService interface {
	didcommsvc.DIDComm

	Register(connID string, options ...medprotocol.ClientOption) error

	Unregister(connID string) error

	GetConnections(...medprotocol.ConnectionOption) ([]string, error)

	Config(connID string) (*medprotocol.Config, error)
}

func WithTimeout(t time.Duration) medprotocol.ClientOption {
	return func(opts *medprotocol.ClientOptions) {
		opts.Timeout = t
	}
}

func New(ctx medprovider.Provider, options ...medprotocol.ClientOption) (*Client, error) {
	svc, err := ctx.Service(medprotocol.Coordination)
	if err != nil {
		return nil, err
	}

	routeSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to route service failed")
	}

	return &Client{
		Event:    routeSvc,
		routeSvc: routeSvc,
		options:  options,
	}, nil
}
