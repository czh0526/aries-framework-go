package legacyconnection

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
)

const (
	LegacyConnection       = "legacyconnection"
	PIURI                  = "https://didcomm.org/connections/1.0"
	InvitationMsgType      = PIURI + "invitation"
	RequestMsgType         = PIURI + "request"
	ResponseMsgType        = PIURI + "response"
	AckMsgType             = "https://didcomm.org/noticication/1.0/ack"
	routerConnsMetadataKey = "routerConnctions"
)

const (
	myNSPrefix    = "my"
	theirNSPrefix = "their"

	InvitationRecipientKey = "invRecipientKey"
)

type Service struct {
}

func (s Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (s Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (s Service) Accept(msgType string) bool {
	//TODO implement me
	panic("implement me")
}

func (s Service) Name() string {
	//TODO implement me
	panic("implement me")
}

func (s Service) Initialize(i interface{}) error {
	//TODO implement me
	panic("implement me")
}

var _ dispatcher.ProtocolService = (*Service)(nil)
