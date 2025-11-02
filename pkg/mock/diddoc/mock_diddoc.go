package diddoc

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	"github.com/stretchr/testify/require"
	"testing"
)

func GetMockDIDDoc(t *testing.T, isDIDCommV2 bool) *did.Doc {
	t.Helper()

	var keyAgreements []did.Verification

	services := []did.Service{
		{
			ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://localhost:8090"),
			RoutingKeys:     []string{MockDIDKey(t)},
			Type:            "did-communication",
			Priority:        0,
			RecipientKeys:   []string{MockDIDKey(t)},
		},
		{
			ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://localhost:9090"),
			RoutingKeys:     []string{MockDIDKey(t)},
			Type:            "did-communication",
			Priority:        1,
			RecipientKeys:   []string{MockDIDKey(t)},
		},
	}

	if isDIDCommV2 {
		services[0].ServiceEndpoint = endpoint.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{
			{
				URI:         "https://localhost:9090",
				Accept:      []string{"didcomm/v2"},
				RoutingKeys: []string{MockDIDKey(t)},
			},
		})
		services[0].Type = "DIDCommMessaging"
		services[0].RoutingKeys = nil
		services[0].RecipientKeys = []string{"#key-2"}
		x25519 := jwk.JWK{}

		err := x25519.UnmarshalJSON([]byte(`
			"kty": "OKP",
			"crv": "X25519",
			"x": "EXXinkMxdA4zGmwpOOpbCXt6Ts6CwyXyEKI3jfHkS3k"
		`))
		if err == nil {
			keyBytes, err := x25519.MarshalJSON()
			if err == nil {
				keyAgreements = append(keyAgreements, did.Verification{
					VerificationMethod: did.VerificationMethod{
						ID:         "did:example:123456789abcdefghi#key-2",
						Type:       "JSONWebKey2020",
						Controller: "did:example:123456789abcdefghi",
						Value:      keyBytes,
					},
				})
			}
		}
	}

	return &did.Doc{
		Context: []string{"https://www.w3id.org/did/v1"},
		ID:      "did:peer:123456789abcdefghi",
		Service: services,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         "did:example:123456789abcdefghi#keys-1",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         "did:example:123456789abcdefghi#keys-2",
				Controller: "did:example:123456789abcdefghi",
				Type:       "Ed25519VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         "did:example:123456789abcdefghw#key2",
				Controller: "did:example:123456789abcdefghw",
				Type:       "RsaVerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
		},
		KeyAgreement: keyAgreements,
	}
}

func GetMockDIDDocWithDIDCommV2Bloc(t *testing.T, id string) *did.Doc {
	t.Helper()

	peerDID := "did:peer:" + id

	return &did.Doc{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      peerDID,
		Service: []did.Service{
			{
				ServiceEndpoint: endpoint.NewDIDCommV2Endpoint(
					[]endpoint.DIDCommV2Endpoint{
						{
							URI:         "https://localhost:8090",
							Accept:      []string{"didcomm/v2"},
							RoutingKeys: []string{MockDIDKey(t)},
						},
					}),
				Type:          "DIDCommMessaging",
				Priority:      0,
				RecipientKeys: []string{MockDIDKey(t)},
			},
		},
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         peerDID + "#key-1",
				Controller: peerDID,
				Type:       "Secp256k1VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         peerDID + "#key-2",
				Controller: peerDID,
				Type:       "Ed25519VerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
			{
				ID:         peerDID + "#key-3",
				Controller: peerDID,
				Type:       "RsaVerificationKey2018",
				Value:      base58.Decode("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"),
			},
		},
		KeyAgreement: []did.Verification{
			{
				Relationship: did.KeyAgreement,
				Embedded:     true,
				VerificationMethod: did.VerificationMethod{
					ID:         peerDID + "#key-4",
					Controller: peerDID,
					Type:       "X25519KeyAgreementKey2019",
					Value:      base58.Decode("JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"),
				},
			},
		},
	}

}

func MockDIDKey(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	d, _ := fingerprint.CreateDIDKey(pub)
	return d
}
