package model

import "github.com/czh0526/aries-framework-go/component/models/did/endpoint"

func NewDIDCommV2Endpoint(endpoints []endpoint.DIDCommV2Endpoint) endpoint.Endpoint {
	return endpoint.NewDIDCommV2Endpoint(endpoints)
}

func NewDIDCommV1Endpoint(uri string) endpoint.Endpoint {
	return endpoint.NewDIDCommV1Endpoint(uri)
}

func NewDIDCoreEndpoint(genericEndpoint interface{}) endpoint.Endpoint {
	return endpoint.NewDIDCoreEndpoint(genericEndpoint)
}
