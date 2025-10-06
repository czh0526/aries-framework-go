package endpoint

import (
	"encoding/json"
	"fmt"
)

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

func (e *Endpoint) URI() (string, error) {
	if len(e.rawDIDCommV2) > 0 {
		return e.rawDIDCommV2[0].URI, nil
	}

	if e.rawDIDCommV1 != "" {
		return stripQuotes(e.rawDIDCommV1), nil
	}

	if e.rawObj != nil {
		switch o := e.rawObj.(type) {
		case []string:
			return o[0], nil
		case [][]byte:
			return string(o[0]), nil
		case []interface{}:
			return fmt.Sprintf("%s", o[0]), nil
		case map[string]interface{}:
			switch uri := o["origins"].(type) {
			case []interface{}:
				return fmt.Sprintf("%s", uri[0]), nil
			default:
				return "", fmt.Errorf("unexpected DIDCore origins object: %s", o)
			}

		default:
			return "", fmt.Errorf("unrecognized DIDCore endpoint object %s", o)
		}
	}

	return "", fmt.Errorf("endpoint URI not found")
}

func (e *Endpoint) Accept() ([]string, error) {
	if len(e.rawDIDCommV2) > 0 {
		return e.rawDIDCommV2[0].Accept, nil
	}

	return nil, fmt.Errorf("endpoint Accept not found")
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

func (e *Endpoint) RoutingKeys() ([]string, error) {
	if len(e.rawDIDCommV2) > 0 {
		return e.rawDIDCommV2[0].RoutingKeys, nil
	}

	return nil, fmt.Errorf("endpoint RoutingKeys not found")
}

func (s *Endpoint) MarshalJSON() ([]byte, error) {
	if len(s.rawDIDCommV2) > 0 {
		return json.Marshal(s.rawDIDCommV2)
	}

	if s.rawDIDCommV1 != "" {
		return []byte(fmt.Sprintf("%q", s.rawDIDCommV1)), nil
	}

	if s.rawObj != nil {
		return json.Marshal(s.rawObj)
	}

	return []byte("null"), nil
}

var _ ServiceEndpoint = (*Endpoint)(nil)

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

func stripQuotes(str string) string {
	if len(str) > 0 {
		if str[0] == '"' {
			str = str[1:]
		}

		if str[len(str)-1] == '"' {
			str = str[:len(str)-1]
		}
	}

	return str
}
