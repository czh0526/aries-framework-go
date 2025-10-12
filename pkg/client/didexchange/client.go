package didexchange

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
)

type protocolService interface {
	service.DIDComm

	AcceptExchangeRequest(connectionID, publicDID, label string, routerConnections []string) error
	AcceptInvitation(connectionID, publicDID, label string, routerConnections []string) error
	CreateImplicitInvitation(inviterLabel, inviterDID, inviteeLabel, inviteeDID string,
		routerConnections []string) error
	CreateConnection(*connection.Record, *did.Doc) error
}
