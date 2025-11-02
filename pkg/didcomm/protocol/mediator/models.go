package mediator

import "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/decorator"

type Request struct {
	Type             string `json:"@type,omitempty"`
	ID               string `json:"@id,omitempty"`
	DIDCommV2        bool   `json:"didcomm_v2,omitempty"`
	decorator.Timing `json:"~timing,omitempty"`
}

type Grant struct {
	Type        string   `json:"@type,omitempty"`
	ID          string   `json:"@id,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"`
	RoutingKeys []string `json:"routing_keys,omitempty"`
}

type Update struct {
	RecipientKey string `json:"recipient_key,omitempty"`
	Action       string `json:"action,omitempty"`
}

type UpdateResponse struct {
	RecipientKey string `json:"recipient_key,omitempty"`
	Action       string `json:"action,omitempty"`
	Result       string `json:"result,omitempty"`
}

type KeylistUpdate struct {
	Type    string   `json:"@type,omitempty"`
	ID      string   `json:"@id,omitempty"`
	Updates []Update `json:"updates,omitempty"`
}

type KeylistUpdateResponse struct {
	Type    string           `json:"@type,omitempty"`
	ID      string           `json:"@id,omitempty"`
	Updates []UpdateResponse `json:"updated,omitempty"`
}
