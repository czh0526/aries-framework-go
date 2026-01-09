package mediator

import (
	msgpickupprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	oobprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/outofband"
)

type RegisterRoute struct {
	ConnectionID string `json:"connectionID"`
}

type ConnectionsRequest struct {
	DIDCommV1Only bool `json:"didcomm_v1"`
	DIDCommV2Only bool `json:"didcomm_v2"`
}

type ConnectionsResponse struct {
	Connections []string `json:"connections"`
}

type StatusRequest struct {
	ConnectionID string `json:"connectionID"`
}

type StatusResponse struct {
	*msgpickupprotocol.Status
}

type BatchPickupRequest struct {
	ConnectionID string `json:"connectionID"`
	Size         int    `json:"batch_size"`
}

type BatchPickupResponse struct {
	MessageCount int `json:"message_count"`
}

type CreateInvitationRequest struct {
	Label     string        `json:"label"`
	Goal      string        `json:"goal"`
	GoalCode  string        `json:"goal_code"`
	Service   []interface{} `json:"service"`
	Protocols []string      `json:"protocols"`
}

type CreateInvitationResponse struct {
	Invitation *oobprotocol.Invitation
}
