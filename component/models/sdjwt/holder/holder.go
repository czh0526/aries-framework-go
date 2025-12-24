package holder

import (
	"crypto"
	"fmt"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	"github.com/go-jose/go-jose/v3/jwt"
	"time"
)

type parseOpts struct {
	detachedPayload           []byte
	sigVerifier               docjose.SignatureVerifier
	issuerSigningAlgorithms   []string
	sdjwtV5Validation         bool
	expectedTypHeader         string
	leewayForClaimsValidation time.Duration
}

type ParseOpt func(opts *parseOpts)

func WithSignatureVerifier(verifier docjose.SignatureVerifier) ParseOpt {
	return func(opts *parseOpts) {
		opts.sigVerifier = verifier
	}
}

type Claim struct {
	Disclosure string
	Name       string
	Value      interface{}
}

func Parse(combinedFormatForIssuance string, opts ...ParseOpt) ([]*Claim, error) {
	// sigVerifier 不能为空，
	// 如果不做校验，用默认的NoopSignatureVerifier
	pOpts := &parseOpts{
		sigVerifier: &NoopSignatureVerifier{},
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	signedJWT, _, err := modeljwt.Parse(cfi.SDJWT,
		modeljwt.WithSignatureVerifier(pOpts.sigVerifier),
		modeljwt.WithJWTDetachedPayload(pOpts.detachedPayload))
	if err != nil {
		return nil, err
	}

	if pOpts.sdjwtV5Validation {
		return nil, fmt.Errorf("sdjwtV5 validation is not yet supported")
	}

	err = common.VerifyDisclosuresInSDJWT(cfi.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	cryptoHash, err := common.GetCryptoHashFromClaims(signedJWT.Payload)
	if err != nil {
		return nil, err
	}

	return getClaims(cfi.Disclosures, cryptoHash)
}

func getClaims(disclosures []string, hash crypto.Hash) ([]*Claim, error) {
	disclosureClaims, err := common.GetDisclosureClaims(disclosures, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosure claims: %v", err)
	}

	var claims []*Claim
	for _, disclosure := range disclosureClaims {
		claims = append(claims, &Claim{
			Disclosure: disclosure.Disclosure,
			Name:       disclosure.Name,
			Value:      disclosure.Value,
		})
	}

	return claims, nil
}

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

type options struct {
	holderVerificationInfo *BindingInfo
}

type Option func(opts *options)

func WithHolderBinding(info *BindingInfo) Option {
	return func(opts *options) {
		opts.holderVerificationInfo = info
	}
}

func WithHolderVerification(info *BindingInfo) Option {
	return func(opts *options) {
		opts.holderVerificationInfo = info
	}
}

func CreateHolderVerification(info *BindingInfo) (string, error) {
	hbJWT, err := modeljwt.NewSigned(info.Payload, info.Headers, info.Signer)
	if err != nil {
		return "", err
	}

	return hbJWT.Serialize(false)
}

func CreatePresentation(combinedFormatForIssuance string, claimsToDisclose []string, opts ...Option) (string, error) {
	hOpts := &options{}

	for _, opt := range opts {
		opt(hOpts)
	}

	cfi := common.ParseCombinedFormatForIssuance(combinedFormatForIssuance)

	if len(cfi.Disclosures) == 0 {
		return "", fmt.Errorf("no disclosure claims found in SD-JWT")
	}

	disclosureMap := common.SliceToMap(cfi.Disclosures)

	for _, ctd := range claimsToDisclose {
		if _, ok := disclosureMap[ctd]; !ok {
			return "", fmt.Errorf("disclosure `%s` not found in SD-JWT", ctd)
		}
	}

	var err error
	var hbJWT string

	if hOpts.holderVerificationInfo != nil {
		hbJWT, err = CreateHolderVerification(hOpts.holderVerificationInfo)
		if err != nil {
			return "", fmt.Errorf("failed to create holder verification: %v", err)
		}
	}

	cf := common.CombineFormatForPresentation{
		SDJWT:              cfi.SDJWT,
		Disclosures:        claimsToDisclose,
		HolderVerification: hbJWT,
	}

	return cf.Serialize(), nil
}

type NoopSignatureVerifier struct{}

func (n NoopSignatureVerifier) Verify(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
	return nil
}

var _ docjose.SignatureVerifier = (*NoopSignatureVerifier)(nil)
