package secp256k1

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	tinksignature "github.com/tink-crypto/tink-go/v2/signature"
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

			err = testSignVerify(kh)
			require.NoError(t, err)
		})
	}
}

func testSignVerify(kh *keyset.Handle) error {
	signer, err := tinksignature.NewSigner(kh)
	if err != nil {
		return fmt.Errorf("signature.NewSigner() failed: %w", err)
	}

	testInputs := []struct {
		message1 []byte
		message2 []byte
	}{
		{
			message1: []byte("this data needs to be signed"),
			message2: []byte("this data needs to be signed"),
		},
		{
			message1: []byte(""),
			message2: []byte(""),
		},
		{
			message1: []byte(""),
			message2: nil,
		},
		{
			message1: nil,
			message2: []byte(""),
		},
		{
			message1: nil,
			message2: nil,
		},
	}

	for _, ti := range testInputs {
		sig, err := signer.Sign(ti.message1)
		if err != nil {
			return fmt.Errorf("signer.Sign(ti.message1) failed: %w", err)
		}
		fmt.Printf("sig: %x \n", sig)
	}

	return nil
}
