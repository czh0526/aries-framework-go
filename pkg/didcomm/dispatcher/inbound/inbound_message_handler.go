package inbound

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
)

type MessageHandler struct {
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
