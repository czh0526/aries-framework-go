package key

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"time"
)

const (
	schemaResV1 = "https://w3id.org/did-resolution/v1"
	schemaDIDV1 = "https://w3id.org/did/v1"

	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	bls12381G2Key2020          = "Bls12381G2Key2020"
	jsonWebKey2020             = "JsonWebKey2020"
)

func (V VDR) Create(didDoc *didmodel.Doc, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
	createDIDOpts := &spivdr.DIDMethodOpts{
		Values: make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(createDIDOpts)
	}

	var (
		publicKey, keyAgr *didmodel.VerificationMethod
		err               error
		didKey            string
		keyID             string
		keyCode           uint64
	)

	if len(didDoc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("verification method is empty")
	}

	switch didDoc.VerificationMethod[0].Type {
	case jsonWebKey2020:
		didKey, keyID, err = fingerprint.CreateDIDKeyByJwk(didDoc.VerificationMethod[0].JSONWebKey())
		if err != nil {
			return nil, err
		}
	default:
		keyCode, err = getKeyCode(&didDoc.VerificationMethod[0])
		if err != nil {
			return nil, err
		}

		didKey, keyID = fingerprint.CreateDIDKeyByCode(keyCode, didDoc.VerificationMethod[0].Value)
	}

	publicKey = didmodel.NewVerificationMethodFromBytes(keyID, didDoc.VerificationMethod[0].Type, didKey,
		didDoc.VerificationMethod[0].Value)

	if didDoc.VerificationMethod[0].Type == ed25519VerificationKey2018 {
		keyAgr, err = keyAgreementFromEd25519(didKey, didDoc.VerificationMethod[0].Value)
		if err != nil {
			return nil, err
		}
	}

	k := createDIDOpts.Values[EncryptionKey]
	if k != nil {
		var ok bool
		keyAgr, ok = k.(*didmodel.VerificationMethod)
		if !ok {
			return nil, fmt.Errorf("encryptionKey not VerificationMethod")
		}
	}

	return &didmodel.DocResolution{
		Context:     []string{schemaResV1},
		DIDDocument: createDoc(publicKey, keyAgr, didKey),
	}, nil
}

func getKeyCode(verificationMethod *didmodel.VerificationMethod) (uint64, error) {
	var keyCode uint64

	switch verificationMethod.Type {
	case ed25519VerificationKey2018:
		keyCode = fingerprint.ED25519PubKeyMultiCodec
	case bls12381G2Key2020:
		keyCode = fingerprint.BLS12381g2PubKeyMultiCodec
	default:
		return 0, fmt.Errorf("not supported public key type: %s", verificationMethod.Type)
	}

	return keyCode, nil
}

func keyAgreementFromEd25519(didKey string, ed25519PubKey []byte) (*didmodel.VerificationMethod, error) {
	curve25518PubKey, err := cryptoutil.PublicEd25519toCurve25519(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	fp := fingerprint.KeyFingerprint(fingerprint.X25519PubKeyMultiCodec, curve25518PubKey)
	keyID := fmt.Sprintf("%s#%s", didKey, fp)
	pubKey := didmodel.NewVerificationMethodFromBytes(keyID, x25519KeyAgreementKey2019, didKey, curve25518PubKey)

	return pubKey, nil
}

func createDoc(pubKey, keyAgreement *didmodel.VerificationMethod, didKey string) *didmodel.Doc {
	t := time.Now()

	kaVerification := make([]didmodel.Verification, 0)
	if keyAgreement != nil {
		kaVerification = []didmodel.Verification{
			*didmodel.NewEmbeddedVerification(keyAgreement, didmodel.KeyAgreement),
		}
	}

	return &didmodel.Doc{
		Context:              []string{schemaDIDV1},
		ID:                   didKey,
		VerificationMethod:   []didmodel.VerificationMethod{*pubKey},
		Authentication:       []didmodel.Verification{*didmodel.NewReferencedVerification(pubKey, didmodel.Authentication)},
		AssertionMethod:      []didmodel.Verification{*didmodel.NewReferencedVerification(pubKey, didmodel.AssertionMethod)},
		CapabilityDelegation: []didmodel.Verification{*didmodel.NewReferencedVerification(pubKey, didmodel.CapabilityDelegation)},
		CapabilityInvocation: []didmodel.Verification{*didmodel.NewReferencedVerification(pubKey, didmodel.CapabilityInvocation)},
		KeyAgreement:         kaVerification,
		Created:              &t,
		Updated:              &t,
	}
}
