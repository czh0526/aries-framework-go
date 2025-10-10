package didexchange

import "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

type MockDIDExchangeSvc struct {
	ProtocolName       string
	HandleFunc         func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc         func(string) bool
}
