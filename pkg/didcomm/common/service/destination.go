package service

import (
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	endpointmodel "github.com/czh0526/aries-framework-go/component/models/did/endpoint"
)

type Destination struct {
	RecipientKeys        []string
	ServiceEndpoint      endpointmodel.Endpoint
	RoutingKeys          []string
	TransportReturnRoute string
	MediaTypeProfiles    []string
	DIDDoc               *didmodel.Doc
}
