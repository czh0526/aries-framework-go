package jwt

import (
	"crypto/ed25519"
	"errors"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
)

type JoseED25519Signer struct {
	privKey []byte
	headers map[string]interface{}
}

func (j JoseED25519Signer) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(j.privKey, data), nil
}

func (j JoseED25519Signer) Headers() docjose.Headers {
	return j.headers
}

func NewEd25519Signer(privKey []byte) *JoseED25519Signer {
	return &JoseED25519Signer{
		privKey: privKey,
		headers: prepareJWSHeaders(nil, signatureEdDSA),
	}
}

func prepareJWSHeaders(headers map[string]interface{}, alg string) map[string]interface{} {
	newHeaders := make(map[string]interface{})

	for k, v := range headers {
		newHeaders[k] = v
	}

	newHeaders[docjose.HeaderAlgorithm] = alg
	return newHeaders
}

type JoseEd25519Verifier struct {
	pubKey []byte
}

func (j JoseEd25519Verifier) Verify(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("alg is not defined")
	}

	if alg != "EdDSA" {
		return errors.New("alg value is not `EdDSA`")
	}

	if ok := ed25519.Verify(j.pubKey, signingInput, signature); !ok {
		return errors.New("signature doesn't match")
	}

	return nil
}

var _ docjose.SignatureVerifier = (*JoseEd25519Verifier)(nil)

func NewEd25519Verifier(pubKey []byte) (*JoseEd25519Verifier, error) {
	if l := len(pubKey); l != ed25519.PublicKeySize {
		return nil, errors.New("bad ed25519 public key length")
	}

	return &JoseEd25519Verifier{
		pubKey: pubKey,
	}, nil
}
