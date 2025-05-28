package endpoint

type Endpoint struct {
	rawDIDCommV2 []DIDCommV2Endpoint
	rawDIDCommV1 string
	rawObj       interface{}
}

type DIDCommV2Endpoint struct {
	URI         string   `json:"uri"`
	Accept      []string `json:"accept,omitempty"`
	RoutingKeys []string `json:"routingKeys,omitempty"`
}

func NewDIDCommV1Endpoint(uri string) Endpoint {
	return Endpoint{
		rawDIDCommV1: uri,
	}
}

func NewDIDCommV2Endpoint(endpoints []DIDCommV2Endpoint) Endpoint {
	endpoint := Endpoint{
		rawDIDCommV2: []DIDCommV2Endpoint{},
	}
	endpoint.rawDIDCommV2 = append(endpoint.rawDIDCommV2, endpoints...)

	return endpoint
}
