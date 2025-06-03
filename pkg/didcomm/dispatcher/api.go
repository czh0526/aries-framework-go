package dispatcher

import "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

type ProtocolService interface {
	service.Handler
	Accept(msgType string) bool
	Name() string
	Initialize(interface{}) error
}
