package endpoint

type EndpointType int

const (
	DIDCommV1 EndpointType = iota
	DIDCommV2
	Generic
)

type ServiceEndpoint interface {
	URI() (string, error)
	Accept() ([]string, error)
	RoutingKeys() ([]string, error)
	Type() EndpointType
}

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

// NewDIDCoreEndpoint creates a generic DIDCore endpoint.
func NewDIDCoreEndpoint(genericEndpoint interface{}) Endpoint {
	return Endpoint{
		rawObj: genericEndpoint,
	}
}

func (e *Endpoint) Type() EndpointType {
	if len(e.rawDIDCommV2) > 0 {
		return DIDCommV2
	}

	if e.rawDIDCommV1 != "" {
		return DIDCommV1
	}

	return Generic
}
