package anoncrypt

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	testkms "github.com/czh0526/aries-framework-go/tests/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPack(t *testing.T) {
	localKms := testkms.NewLocalKMS(t)

	alicePubKey, _, err := localKms.ExportPubKeyBytes("y5XryGshZExvDsdm-WvKTN521T3cOudKX8T358CpTfA")
	require.NoError(t, err)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, localKms)
		aliceProposalToCarol := []byte(`{
    "@type": "https://didcomm.org/out-of-band/1.0/invitation",
    "@id": "邀请的唯一UUID",
    "label": "Alice's Agent",
    "goal_code": "issue-vc",
    "goal": "To issue a digital driver's license",
    "services": [
        {
            "id": "#inline-0",
            "type": "did-communication",
            "recipientKeys": [
                "did:key:z6MkpTHR..."
            ],
            "serviceEndpoint": "https://agent.example.com"
        }
    ],
    "handshake_protocols": [
        "https://didcomm.org/didexchange/1.0"
    ]
}`)

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = packer.Pack("", aliceProposalToCarol, nil, [][]byte{alicePubKey})
		require.NoError(t, err)
		fmt.Printf("envelope ==> %s\n", enc)
		env, err = packer.Unpack(enc)
		require.NoError(t, err)
		fmt.Printf("%#v\n", env)
	})
}
