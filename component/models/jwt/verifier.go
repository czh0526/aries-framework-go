package jwt

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	sigverifier "github.com/czh0526/aries-framework-go/component/models/signature/verifier"
	"strings"
)

type KeyResolver interface {
	Resolve(what, kid string) (*sigapi.PublicKey, error)
}

type KeyResolveFunc func(what, kid string) (*sigapi.PublicKey, error)

func (k KeyResolveFunc) Resolve(what, kid string) (*sigapi.PublicKey, error) {
	return k(what, kid)
}

type BasicVerifier struct {
	resolver          KeyResolver
	compositeVerifier *jose.CompositeAlgSigVerifier
}

func (v BasicVerifier) Verify(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
	return v.compositeVerifier.Verify(joseHeaders, payload, signingInput, signature)
}

var _ jose.SignatureVerifier = (*BasicVerifier)(nil)

type signatureVerifier func(pubKey *sigapi.PublicKey, message, signature []byte) error

func getVerifier(resolver KeyResolver, signatureVerifier signatureVerifier) jose.SignatureVerifier {
	return jose.SignatureVerifierFunc(func(joseHeaders jose.Headers, payload, signingInput, signature []byte) error {
		return verifySignature(resolver, signatureVerifier,
			joseHeaders, payload, signingInput, signature)
	})
}

func verifySignature(resolver KeyResolver, signatureVerifier signatureVerifier,
	joseHeaders jose.Headers, _, signingInput, signature []byte) error {
	kid, _ := joseHeaders.KeyID()

	if !strings.HasPrefix(kid, "did:") {
		return fmt.Errorf("kid %s is not DID", kid)
	}

	pubKey, err := resolver.Resolve(strings.Split(kid, "#")[0], strings.Split(kid, "#")[1])
	if err != nil {
		return err
	}

	return signatureVerifier(pubKey, signingInput, signature)
}

func NewVerifier(resolver KeyResolver) *BasicVerifier {
	verifiers := []sigverifier.SignatureVerifier{
		sigverifier.NewECDSAES256SignatureVerifier(),
		sigverifier.NewECDSAES384SignatureVerifier(),
		sigverifier.NewECDSAES521SignatureVerifier(),
		sigverifier.NewEd25519SignatureVerifier(),
		sigverifier.NewECDSASecp256k1SignatureVerifier(),
		sigverifier.NewRSAPS256SignatureVerifier(),
		sigverifier.NewRSARS256SignatureVerifier(),
	}

	algVerifiers := make([]jose.AlgSignatureVerifier, 0, len(verifiers))
	for _, v := range verifiers {
		algVerifiers = append(algVerifiers, jose.AlgSignatureVerifier{
			Alg:      v.Algorithm(),
			Verifier: getVerifier(resolver, v.Verify),
		})
	}

	compositeVrifier := jose.NewCompositeAlgSigVerifier(algVerifiers[0], algVerifiers[1:]...)

	return &BasicVerifier{
		resolver:          resolver,
		compositeVerifier: compositeVrifier,
	}
}
