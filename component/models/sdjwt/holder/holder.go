package holder

import (
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/go-jose/go-jose/v3/jwt"
)

type BindingPayload struct {
	Nonce    string           `json:"nonce,omitempty"`
	Audience string           `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
}

type BindingInfo struct {
	Payload BindingPayload
	Signer  docjose.Signer
	Headers docjose.Headers
}

func CreateHolderVerification(info *BindingInfo) (string, error) {
	hbJWT, err := modeljwt.NewSigned(info.Payload, info.Headers, info.Signer)
	if err != nil {
		return "", err
	}

	return hbJWT.Serialize(false)
}

type NoopSignatureVerifier struct{}

func (n NoopSignatureVerifier) Verify(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

var _ docjose.SignatureVerifier = (*NoopSignatureVerifier)(nil)
