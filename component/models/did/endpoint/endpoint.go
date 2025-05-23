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
