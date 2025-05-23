package did

import "github.com/czh0526/aries-framework-go/component/models/did/endpoint"

type Service struct {
	ID                       string
	Type                     interface{}
	Priority                 interface{}
	RecipientKeys            []string
	RoutingKeys              []string
	ServiceEndpoint          endpoint.Endpoint
	Accept                   []string
	Properties               map[string]interface{}
	recipientKeysRelativeURL map[string]bool
	routingKeysRelativeURL   map[string]bool
	relativeURL              bool
}
