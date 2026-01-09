package authcrypt

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	testkms "github.com/czh0526/aries-framework-go/tests/kms"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPack(t *testing.T) {
	localKms := testkms.NewLocalKMS(t)

	alicePubKey, _, err := localKms.ExportPubKeyBytes("lE68f6Mod81s1jwxfE7TbmZnHfLDUu5rh5fvatYMk50")
	require.NoError(t, err)
	bobPubKey, _, err := localKms.ExportPubKeyBytes("e6_zFLuWUuv9VivHNMbByZdOTxVaRfCiEqu7QAMRaqs")
	require.NoError(t, err)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, localKms)
		aliceProposalToCarol := []byte(`{
  "@type": "https://didcomm.org/out-of-band/1.0/invitation",
  "@id": "test-connection-001",
  "label": "Alice's Agent",
  "goal_code": "issue-vc", 
  "goal": "To issue a digital driver's license",
  "services": [
    {
      "id": "#svc-1",
      "type": "did-communication",
      "recipientKeys": ["did:key:z6MktDeNJUVdP8funQs9UnaGUnHWxM1Dy61uPEmmDZ1bDudL"],
      "serviceEndpoint": "https://127.0.0.1:8081"
    }
  ],
  "handshake_protocols": ["https://didcomm.org/didexchange/1.0"]
}`)

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = packer.Pack("", aliceProposalToCarol, alicePubKey, [][]byte{bobPubKey})
		require.NoError(t, err)
		fmt.Printf("envelope ==> %s\n", enc)
		env, err = packer.Unpack(enc)
		require.NoError(t, err)
		fmt.Printf("%#v\n", env)
	})
}
