package secp256k1

import (
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"testing"
)

func TestKeyTemplate(t *testing.T) {
	derKeyTemplate, err := DERKeyTemplate()
	require.NoError(t, err)

	ieeeKeyTemplate, err := IEEEP1363KeyTemplate()
	require.NoError(t, err)

	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "SECP256K1",
			template: derKeyTemplate,
		},
		{
			name:     "SECP256K1",
			template: ieeeKeyTemplate,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var kh *keyset.Handle

			kh, err = keyset.NewHandle(tc.template)
			require.NoError(t, err)
			require.NotEmpty(t, kh)
		})
	}
}
