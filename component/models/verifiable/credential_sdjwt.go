package verifiable

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/holder"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/issuer"
)

type marshalDisclosureOpts struct {
	includeAllDisclosures bool
	disclosureIfAvailable []string
	disclosureRequired    []string
	holderBinding         *holder.BindingInfo
	signer                jose.Signer
	signingKeyID          string
	sdjwtVersion          common.SDJWTVersion
}

type MarshalDisclosureOption func(opts *marshalDisclosureOpts)

func DiscloseAll() MarshalDisclosureOption {
	return func(opts *marshalDisclosureOpts) {
		opts.includeAllDisclosures = true
	}
}

func (vc *Credential) MarshalWithDisclosure(opts ...MarshalDisclosureOption) (string, error) {
	sdJWTVersion := common.SDJWTVersionDefault
	if vc.SDJWTVersion != 0 {
		sdJWTVersion = vc.SDJWTVersion
	}

	options := &marshalDisclosureOpts{
		sdjwtVersion: sdJWTVersion,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.includeAllDisclosures && (len(options.disclosureIfAvailable) > 0 || len(options.disclosureRequired) > 0) {
		return "", errors.New("incompatible options provided")
	}

	if vc.JWT != "" && vc.SDJWTHashAlg != "" {
		return filterSDJWTVC(vc, options)
	}

	if options.signer == nil {
		return "", fmt.Errorf("credential needs signer to create SD-JWT")
	}

	return createSDJWTPresentation(vc, options)
}

func filterSDJWTVC(vc *Credential, options *marshalDisclosureOpts) (string, error) {
	disclosureCodes, err := filterDisclosureCodes(vc.SDJWTDisclosures, options)
	if err != nil {
		return "", err
	}

	cf := common.CombinedFormatForPresentation{
		SDJWT:              vc.JWT,
		Disclosures:        disclosureCodes,
		HolderVerification: vc.SDHolderBinding,
	}

	if options.holderBinding != nil {
		cf.HolderVerification, err = holder.CreateHolderVerification(options.holderBinding)
		if err != nil {
			return "", fmt.Errorf("failed to create holder binding: %w", err)
		}
	}

	return cf.Serialize(), nil
}

type MakeSDJWTOpts struct {
	hashAlg               crypto.Hash
	version               common.SDJWTVersion
	recursiveClaimsObject []string
	alwaysIncludeObjects  []string
	nonSDClaims           []string
}

type MakeSDJWTOption func(opts *MakeSDJWTOpts)

func MakeSDJWTWithVersion(version common.SDJWTVersion) MakeSDJWTOption {
	return func(opts *MakeSDJWTOpts) {
		opts.version = version
	}
}

func createSDJWTPresentation(vc *Credential, options *marshalDisclosureOpts) (string, error) {
	issued, err := makeSDJWT(vc, options.signer, options.signingKeyID, MakeSDJWTWithVersion(options.sdjwtVersion))
}

func makeSDJWT(vc *Credential, signer jose.Signer, signingKeyID string,
	options ...MakeSDJWTOption) (*issuer.SelectiveDisclosureJWT, error) {

	sdJWTVersion := common.SDJWTVersionDefault
	if vc.SDJWTVersion != 0 {
		sdJWTVersion = vc.SDJWTVersion
	}

	opts := &MakeSDJWTOpts{
		version: sdJWTVersion,
	}

	for _, opt := range options {
		opt(opts)
	}

	claims, err := vc.JWTClaims(false)
}
