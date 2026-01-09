package outofband

import didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

const (
	Name = "out-of-band"
)

type Service struct {
	didcommsvc.Action
	didcommsvc.Message
	callbackChannel chan *callback
}

type callback struct {
	msg      didcommsvc.DIDCommMsg
	myDID    string
	theirDID string
	ctx      *context
}

type Action struct {
	PIID         string
	Msg          didcommsvc.DIDCommMsgMap
	ProtocolName string
	MyDID        string
	TheirDID     string
}

type context struct {
	Action
	CurrentStateName   string
	Inbound            bool
	ReuseAnyConnection bool
	ReuseConnection    string
	ConnectionID       string
	Invitation         *Invitation
}
