package endpoint

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewEndpoint(t *testing.T) {
	uri := "uri"
	accept := []string{"accept"}
	routingkeys := []string{"key1"}

	// V2 Type
	didCommV2Endpoint := Endpoint{
		rawDIDCommV2: []DIDCommV2Endpoint{
			{
				URI:         uri,
				Accept:      accept,
				RoutingKeys: routingkeys,
			},
		},
	}

	ep := NewDIDCommV2Endpoint([]DIDCommV2Endpoint{
		{
			URI:         uri,
			Accept:      accept,
			RoutingKeys: routingkeys,
		},
	})
	require.EqualValues(t, didCommV2Endpoint, ep)
	require.Equal(t, DIDCommV2, ep.Type())

	// V1 Type
	didCommV1Endpoint := Endpoint{
		rawDIDCommV1: uri,
	}
	ep = NewDIDCommV1Endpoint(uri)
	require.EqualValues(t, didCommV1Endpoint, ep)
	require.Equal(t, DIDCommV1, ep.Type())

	// Generic Type
	didCoreEndpoint := Endpoint{
		rawObj: []string{uri, "uri2"},
	}
	ep = NewDIDCoreEndpoint([]string{uri, "uri2"})
	require.EqualValues(t, didCoreEndpoint, ep)
	require.Equal(t, Generic, ep.Type())
}
