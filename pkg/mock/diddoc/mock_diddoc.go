package diddoc

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	"github.com/stretchr/testify/require"
	"testing"
)

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
