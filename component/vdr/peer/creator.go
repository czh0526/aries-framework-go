package peer

import (
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"github.com/google/uuid"
	"time"
)

const (
	schemaResV1                = "https://w3id.org/did-resolution/v1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	jsonWebKey2020             = "JsonWebKey2020"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	didcommV2MediaType         = "didcomm/v2"
)

func (v *VDR) Create(didDoc *didmodel.Doc, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error) {
	docOpts := &spivdr.DIDMethodOpts{
		Values: make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(docOpts)
	}

	store := false

	storeOpt := docOpts.Values["store"]
	if storeOpt != nil {
		var ok bool

		store, ok = storeOpt.(bool)
		if !ok {
			return nil, fmt.Errorf("store opt not boolean")
		}
	}

	if !store {
		docResolution, err := build(didDoc, docOpts)
		if err != nil {
			return nil, fmt.Errorf("create peer DID: %w", err)
		}

		didDoc = docResolution.DIDDocument
	}

	if err := v.storeDID(didDoc, nil); err != nil {
		return nil, err
	}

	return &didmodel.DocResolution{
		Context:     []string{schemaResV1},
		DIDDocument: didDoc,
	}, nil
}

func build(didDoc *didmodel.Doc, docOpts *spivdr.DIDMethodOpts) (*didmodel.DocResolution, error) {
	if len(didDoc.VerificationMethod) == 0 && len(didDoc.KeyAgreement) == 0 {
		return nil, fmt.Errorf("verification method and key agreement are empty, at least one should be set")
	}

	mainVM, keyAgreementVM, err := buildDIDVMs(didDoc)
	if err != nil {
		return nil, err
	}

	var service []didmodel.Service

	for i := range didDoc.Service {
		if didDoc.Service[i].ID == "" {
			didDoc.Service[i].ID = uuid.New().String()
		}
	}

	t := time.Now()

	assertion := []didmodel.Verification{
		{
			VerificationMethod: mainVM[0],
			Relationship:       didmodel.AssertionMethod,
		},
	}

	authentication := []didmodel.Verification{
		{
			VerificationMethod: mainVM[0],
			Relationship:       didmodel.Authentication,
		},
	}

	var keyAgreement []didmodel.Verification

	verificationMethods := mainVM

	if keyAgreementVM != nil {
		verificationMethods = append(verificationMethods, keyAgreementVM...)

		for _, ka := range keyAgreementVM {
			keyAgreement = append(keyAgreement, didmodel.Verification{
				VerificationMethod: ka,
				Relationship:       didmodel.KeyAgreement,
			})
		}
	}

	didDoc, err = NewDoc(
		verificationMethods,
		didmodel.WithService(service),
		didmodel.WithCreatedTime(t),
		didmodel.WithUpdatedTime(t),
		didmodel.WithAuthentication(authentication),
		didmodel.WithAssertion(assertion),
		didmodel.WithKeyAgreement(keyAgreement))
	if err != nil {
		return nil, err
	}

	return &didmodel.DocResolution{
		DIDDocument: didDoc,
	}, nil
}

func buildDIDVMs(didDoc *didmodel.Doc) ([]didmodel.VerificationMethod, []didmodel.VerificationMethod, error) {
	var mainVM, keyAgreementVM []didmodel.VerificationMethod

	for _, vm := range didDoc.VerificationMethod {
		switch vm.Type {
		case ed25519VerificationKey2018:
			mainVM = append(mainVM, *didmodel.NewVerificationMethodFromBytes(vm.ID, ed25519VerificationKey2018,
				"#id", vm.Value))
		case jsonWebKey2020:
			publicKey1, err := didmodel.NewVerificationMethodFromJWK(vm.ID, jsonWebKey2020,
				"#id", vm.JSONWebKey())
			if err != nil {
				return nil, nil, err
			}
			mainVM = append(mainVM, *publicKey1)

		default:
			return nil, nil, fmt.Errorf("unsupported verification method public key type: %s", vm.Type)
		}
	}

	for _, ka := range didDoc.KeyAgreement {
		switch ka.VerificationMethod.Type {
		case x25519KeyAgreementKey2019:
			keyAgreementVM = append(keyAgreementVM, *didmodel.NewVerificationMethodFromBytes(
				ka.VerificationMethod.ID, x25519KeyAgreementKey2019, "",
				ka.VerificationMethod.Value))

		case jsonWebKey2020:
			kaVM, err := didmodel.NewVerificationMethodFromJWK(ka.VerificationMethod.ID, jsonWebKey2020, "",
				ka.VerificationMethod.JSONWebKey())
			if err != nil {
				return nil, nil, err
			}

			keyAgreementVM = append(keyAgreementVM, *kaVM)

		default:
			return nil, nil, fmt.Errorf("unsupported verification method public key type: %s",
				ka.VerificationMethod.Type)
		}
	}

	return mainVM, keyAgreementVM, nil
}
