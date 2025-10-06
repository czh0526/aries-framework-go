package inbound

import (
	"fmt"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries/api"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	"time"
)

type MessageHandler struct {
	didConnectionStore     didstore.ConnectionStore
	didcommV2Handler       *middleware.DIDCommMessageMiddleware
	msgSvcProvider         api.MessageServiceProvider
	services               []dispatcher.ProtocolService
	getDIDsBackOffDuration time.Duration
	getDIDsMaxRetries      uint64
	messenger              service.InboundMessenger
	vdr                    vdrapi.Registry
	initialized            bool
}

func (mh *MessageHandler) HandleInboundEnvelope(envelope *transport.Envelope) error {
	fmt.Println("Handle inbound envelope: has not be implemented yet")
	return nil
}

func (mh *MessageHandler) HandlerFunc() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		return mh.HandleInboundEnvelope(envelope)
	}
}

func (mh *MessageHandler) Initialize(p provider) {
	return
}

type provider interface {
}

func NewInboundMessageHandler(p provider) *MessageHandler {
	h := MessageHandler{}
	h.Initialize(p)

	return &h
}
