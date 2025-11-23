package basic

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
)

const (
	MessageRequestType = "https://didcomm.org/basicmessage/1.0/message"

	errNameAndHandleMandatory = "service name and basic message handle is mandatory"

	errFailedToDecodeMsg = "unable to code incoming DID comm message: %w"

	basicMessage = "basicMessage"
)

var logger = log.New("aries-framework/basicmsg")

type MessageHandle func(message Message, ctx service.DIDCommContext) error

type MessageService struct {
	name   string
	handle MessageHandle
}

func NewMessageService(name string, handle MessageHandle) (*MessageService, error) {
	if name == "" || handle == nil {
		return nil, fmt.Errorf(errNameAndHandleMandatory)
	}

	return &MessageService{
		name:   name,
		handle: handle,
	}, nil
}

func (m *MessageService) Name() string {
	return m.name
}

func (m *MessageService) Accept(msgType string, purpose []string) bool {
	return msgType == MessageRequestType
}

func (m *MessageService) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	basicMsg := Message{}

	err := msg.Decode(&basicMsg)
	if err != nil {
		return "", fmt.Errorf(errFailedToDecodeMsg, err)
	}

	return "", m.handle(basicMsg, ctx)
}
