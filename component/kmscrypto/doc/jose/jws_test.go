package jose

import (
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHeaders_GetKeyID(t *testing.T) {
	kid, ok := Headers{"kid": "key id"}.KeyID()
	require.True(t, ok)
	require.Equal(t, "key id", kid)

	kid, ok = Headers{"kid": 777}.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)

	kid, ok = Headers{}.KeyID()
	require.False(t, ok)
	require.Empty(t, kid)
}

func TestNewCompositeAlgSignatureVerifier(t *testing.T) {
	verifier := NewCompositeAlgSigVerifier(AlgSignatureVerifier{
		Alg: "EdDSA",
		Verifier: SignatureVerifierFunc(
			func(joseHeaders Headers, payload, signingInput, signature []byte) error {
				return errors.New("signature is invalid")
			},
		),
	})

	err := verifier.Verify(Headers{"alg": "EdDSA"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "signature is invalid")
}

func TestDefaultSigningInputVerifier_Verify(t *testing.T) {
	verifier := DefaultSigningInputVerifier(
		func(joseHeaders Headers, payload, signingInput, signature []byte) error {
			return errors.New("signature is invalid")
		},
	)

	err := verifier.Verify(Headers{"alg": "EdDSA"}, nil, nil, nil)
	require.Error(t, err)
	require.EqualError(t, err, "signature is invalid")
}

func TestJSONWebSignature_SerializeCompact(t *testing.T) {
	headers := Headers{"alg": "EdDSA", "typ": "JWT"}
	payload := []byte("payload")

	jws, err := NewJWS(headers, nil, payload,
		&testSigner{
			headers:   Headers{"alg": "dummy", "b64": false},
			signature: []byte("signature"),
		})
	require.NoError(t, err)

	jswCompact, err := jws.SerializeCompact(false)
	require.NoError(t, err)
	require.NotEmpty(t, jswCompact)
}

type testSigner struct {
	headers   Headers
	signature []byte
	err       error
}

func (t testSigner) Sign(data []byte) ([]byte, error) {
	return t.signature, t.err
}

func (t testSigner) Headers() Headers {
	return t.headers
}

var _ Signer = (*testSigner)(nil)
