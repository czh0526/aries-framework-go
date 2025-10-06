package did

import (
	"errors"
	"fmt"
)

type VerificationRelationship int

const (
	VerificationRelationshipGeneral VerificationRelationship = iota
	Authentication
	AssertionMethod
	CapabilityDelegation
	CapabilityInvocation
	KeyAgreement
)

type Verification struct {
	VerificationMethod VerificationMethod
	Relationship       VerificationRelationship
	Embedded           bool
}

func populateRawVerification(context, baseURI, didID string, verifications []Verification) ([]interface{}, error) {
	var rawVerifications []interface{}

	for _, v := range verifications {
		if v.Embedded {
			vm, err := populateRawVerificationMethod(context, didID, baseURI, &v.VerificationMethod)
			if err != nil {
				return nil, err
			}

			rawVerifications = append(rawVerifications, vm)

		} else {
			if v.VerificationMethod.relativeURL {
				rawVerifications = append(rawVerifications,
					makeRelativeDIDURL(v.VerificationMethod.ID, baseURI, didID))
			} else {
				rawVerifications = append(rawVerifications, v.VerificationMethod.ID)
			}
		}
	}
	return rawVerifications, nil
}

func populateVerificationRelationships(doc *Doc, raw *rawDoc) error {
	authetications, err := populateVerification(doc, raw.Authentication, Authentication)
	if err != nil {
		return fmt.Errorf("populate authentications failed: %w", err)
	}

	doc.Authentication = authetications

	assertionMethods, err := populateVerification(doc, raw.AssertionMethod, AssertionMethod)
	if err != nil {
		return fmt.Errorf("populate assertion methods failed: %w", err)
	}

	doc.AssertionMethod = assertionMethods

	capabilityDelegations, err := populateVerification(doc, raw.CapabilityDelegation, CapabilityDelegation)
	if err != nil {
		return fmt.Errorf("populate capability delegations failed: %w", err)
	}

	doc.CapabilityDelegation = capabilityDelegations

	capabilityInvocation, err := populateVerification(doc, raw.CapabilityInvocation, CapabilityInvocation)
	if err != nil {
		return fmt.Errorf("populate capability invocation failed: %w", err)
	}

	doc.CapabilityInvocation = capabilityInvocation

	keyAgreements, err := populateVerification(doc, raw.KeyAgreement, KeyAgreement)
	if err != nil {
		return fmt.Errorf("populate key agreements failed: %w", err)
	}

	doc.KeyAgreement = keyAgreements

	return nil
}

func populateVerification(doc *Doc, rawVerification []interface{},
	relationship VerificationRelationship) ([]Verification, error) {
	var vms []Verification

	for _, rawVerification := range rawVerification {
		v, err := getVerification(doc, rawVerification, relationship)
		if err != nil {
			return nil, err
		}

		vms = append(vms, v...)
	}

	return vms, nil
}

func getVerification(doc *Doc, rawVerification interface{},
	relationship VerificationRelationship) ([]Verification, error) {
	vm := doc.VerificationMethod
	context, _ := ContextPeekString(doc.Context)

	keyID, keyIDExist := rawVerification.(string)
	if keyIDExist {
		return getVerificationsByKeyID(doc.ID, doc.processingMeta.baseURI, vm, relationship, keyID)
	}

	m, ok := rawVerification.(map[string]interface{})
	if !ok {
		return nil, errors.New("rawVerification is not map[string]interface{}")
	}

	if context == contextV011 {
		keyID, keyIDExist = m[jsonldPublicKey].(string)
		if keyIDExist {
			return getVerificationsByKeyID(doc.ID, doc.processingMeta.baseURI, vm, relationship, keyID)
		}
	}

	if context == contextV12019 {
		keyIDs, keyIDsExist := m[jsonldPublicKey].([]interface{})
		if keyIDsExist {
			return getVerificationsByKeyID(doc.ID, doc.processingMeta.baseURI, vm, relationship, keyIDs...)
		}
	}

	pk, err := populateVerificationMethod(context, doc.ID, doc.processingMeta.baseURI, []map[string]interface{}{m})
	if err != nil {
		return nil, err
	}

	return []Verification{
		{
			VerificationMethod: pk[0],
			Relationship:       relationship,
			Embedded:           true,
		},
	}, nil
}

func getVerificationsByKeyID(didID, baseURI string, vm []VerificationMethod,
	relationship VerificationRelationship, keyIDs ...interface{}) ([]Verification, error) {

	var vms []Verification

	for _, keyID := range keyIDs {
		keyExist := false
		if keyID == "" {
			continue
		}

		for _, v := range vm {
			if v.ID == keyID || v.ID == resolveRelativeDIDURL(didID, baseURI, keyID) {
				vms = append(vms, Verification{
					VerificationMethod: v,
					Relationship:       relationship,
				})
				keyExist = true
			}
		}

		if !keyExist {
			return nil, fmt.Errorf("key %s does not exist in did doc verification method", keyID)
		}
	}

	return vms, nil
}
