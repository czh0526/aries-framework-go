package jwt

import (
	"fmt"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	sigverifier "github.com/czh0526/aries-framework-go/component/models/signature/verifier"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"strings"
)

const (
	signatureEdDSA = "EdDSA"
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
	compositeVerifier *docjose.CompositeAlgSigVerifier
}

func (v BasicVerifier) Verify(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
	return v.compositeVerifier.Verify(joseHeaders, payload, signingInput, signature)
}

var _ docjose.SignatureVerifier = (*BasicVerifier)(nil)

type signatureVerifier func(pubKey *sigapi.PublicKey, message, signature []byte) error

func getPublicKeyVerifier(publicKey *sigapi.PublicKey, v sigverifier.SignatureVerifier) docjose.SignatureVerifier {
	return docjose.SignatureVerifierFunc(func(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
		alg, ok := joseHeaders.Algorithm()
		if !ok {
			return fmt.Errorf("`alg` JOSE header is not present")
		}
		if alg != v.Algorithm() {
			return fmt.Errorf("alg %s does not match public key algorithm %s", alg, v.Algorithm())
		}

		return v.Verify(publicKey, signingInput, signature)
	})
}

func getVerifier(resolver KeyResolver, signatureVerifier signatureVerifier) docjose.SignatureVerifier {
	return docjose.SignatureVerifierFunc(func(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
		return verifySignature(resolver, signatureVerifier,
			joseHeaders, payload, signingInput, signature)
	})
}

func verifySignature(resolver KeyResolver, signatureVerifier signatureVerifier,
	joseHeaders docjose.Headers, _, signingInput, signature []byte) error {
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

	algVerifiers := make([]docjose.AlgSignatureVerifier, 0, len(verifiers))
	for _, v := range verifiers {
		algVerifiers = append(algVerifiers, docjose.AlgSignatureVerifier{
			Alg:      v.Algorithm(),
			Verifier: getVerifier(resolver, v.Verify),
		})
	}

	compositeVrifier := docjose.NewCompositeAlgSigVerifier(algVerifiers[0], algVerifiers[1:]...)

	return &BasicVerifier{
		resolver:          resolver,
		compositeVerifier: compositeVrifier,
	}
}

func GetVerifier(publicKey *sigapi.PublicKey) (*BasicVerifier, error) {
	keyType, err := publicKey.JWK.KeyType()
	if err != nil {
		return nil, err
	}

	var v sigverifier.SignatureVerifier
	switch keyType {
	case spikms.ECDSAP256TypeDER, spikms.ECDSAP256TypeIEEEP1363:
		v = sigverifier.NewECDSAES256SignatureVerifier()
	case spikms.ECDSAP384TypeDER, spikms.ECDSAP384TypeIEEEP1363:
		v = sigverifier.NewECDSAES384SignatureVerifier()
	case spikms.ECDSAP521TypeDER, spikms.ECDSAP521TypeIEEEP1363:
		v = sigverifier.NewECDSAES521SignatureVerifier()
	case spikms.ED25519Type:
		v = sigverifier.NewEd25519SignatureVerifier()
	case spikms.ECDSASecp256k1TypeDER, spikms.ECDSASecp256k1TypeIEEEP1363:
		v = sigverifier.NewECDSASecp256k1SignatureVerifier()
	case spikms.RSAPS256Type:
		v = sigverifier.NewRSAPS256SignatureVerifier()
	case spikms.RSARS256Type:
		v = sigverifier.NewRSARS256SignatureVerifier()
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	compositeVerifier := docjose.NewCompositeAlgSigVerifier(
		docjose.AlgSignatureVerifier{
			Alg:      v.Algorithm(),
			Verifier: getPublicKeyVerifier(publicKey, v),
		})

	return &BasicVerifier{
		compositeVerifier: compositeVerifier,
	}, nil
}
