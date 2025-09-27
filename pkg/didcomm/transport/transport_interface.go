package transport

import "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

type Envelope struct {
	MediaTypeProfile string
	Message          []byte
	FromKey          []byte
	ToKeys           []string
	ToKey            []byte
}

type Packager interface {
	PackMessage(envelope *Envelope) ([]byte, error)
	UnpackMessage(encMessage []byte) (*Envelope, error)
}

type InboundMessageHandler func(envelope *Envelope) error

type Provider interface {
	InboundMessageHandler() InboundMessageHandler
	Packager() Packager
	AriesFrameworkID() string
}

type OutboundTransport interface {
	Start(prov Provider) error

	Send(data []byte, destination *service.Destination) (string, error)

	AcceptRecipient([]string) bool

	Accept(string) bool
}

type InboundTransport interface {
	Start(prov Provider) error

	Stop() error

	Endpoint() string
}
