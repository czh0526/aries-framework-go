package outofband

import didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

const (
	Name = "out-of-band"
)

type Action struct {
	PIID         string
	Msg          didcommsvc.DIDCommMsgMap
	ProtocolName string
	MyDID        string
	TheirDID     string
}
