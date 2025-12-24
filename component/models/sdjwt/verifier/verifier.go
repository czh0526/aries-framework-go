package verifier

import (
	"crypto"
	"encoding/json"
	"fmt"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	docjwk "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	sigverifier "github.com/czh0526/aries-framework-go/component/models/signature/api"
	"github.com/czh0526/aries-framework-go/component/models/util/maphelpers"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"time"
)

type parseOpts struct {
	detachedPayload []byte
	sigVerifier     docjose.SignatureVerifier

	issuerSigningAlgorithm []string
	holderSigningAlgorithm []string

	holderVerificationRequired            bool
	expectedAudienceForHolderVerification string
	expectedNonceForHolderVerification    string

	leewayForClaimsValidation time.Duration
	expectedTypHeader         string
}

type ParseOpt func(opts *parseOpts)

func WithSignatureVerifier(signatureVerifier docjose.SignatureVerifier) ParseOpt {
	return func(opts *parseOpts) {
		opts.sigVerifier = signatureVerifier
	}
}

func WithExpectedTypeHeader(typ string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedTypHeader = typ
	}
}

func WithLeewayForClaimsValidation(duration time.Duration) ParseOpt {
	return func(opts *parseOpts) {
		opts.leewayForClaimsValidation = duration
	}
}

func WithHolderVerificationRequired(flag bool) ParseOpt {
	return func(opts *parseOpts) {
		opts.holderVerificationRequired = flag
	}
}

func WithExpectedAudienceForHolderVerification(audience string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedAudienceForHolderVerification = audience
	}
}

func WithExpectedNonceForHolderVerification(nonce string) ParseOpt {
	return func(opts *parseOpts) {
		opts.expectedNonceForHolderVerification = nonce
	}
}

func Parse(combinedFormatForPresentation string, opts ...ParseOpt) (map[string]interface{}, error) {
	defaultSigninglgorithm := []string{"EdDSA", "RS256"}
	pOpts := &parseOpts{
		issuerSigningAlgorithm:    defaultSigninglgorithm,
		holderSigningAlgorithm:    defaultSigninglgorithm,
		leewayForClaimsValidation: josejwt.DefaultLeeway,
	}

	for _, opt := range opts {
		opt(pOpts)
	}

	cfp := common.ParseCombinedFormatForPresentation(combinedFormatForPresentation)

	signedJWT, err := validateIssuerSignedSDJWT(cfp.SDJWT, cfp.Disclosures, pOpts)
	if err != nil {
		return nil, err
	}

	err = common.VerifyDisclosuresInSDJWT(cfp.Disclosures, signedJWT)
	if err != nil {
		return nil, err
	}

	if pOpts.expectedTypHeader != "" {
		err = common.VerifyTyp(signedJWT.Headers, pOpts.expectedTypHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to verify typ header: %w", err)
		}
	}

	err = runHolderVerification(signedJWT, cfp.HolderVerification, pOpts)
	if err != nil {
		return nil, fmt.Errorf("run holder verification: %w", err)
	}

	cryptoHash, err := common.GetCryptoHashFromClaims(signedJWT.Payload)
	if err != nil {
		return nil, err
	}

	return getDisclosedClaims(cfp.Disclosures, signedJWT, cryptoHash)
}

func validateIssuerSignedSDJWT(sdjwt string, disclosures []string, pOpts *parseOpts) (*modeljwt.JSONWebToken, error) {
	signedJWT, _, err := modeljwt.Parse(sdjwt,
		modeljwt.WithSignatureVerifier(pOpts.sigVerifier),
		modeljwt.WithJWTDetachedPayload(pOpts.detachedPayload))
	if err != nil {
		return nil, err
	}

	err = common.VerifySigningAlg(signedJWT.Headers, pOpts.issuerSigningAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to verify issuer signing algorithm: %w", err)
	}

	err = common.VerifyJWT(signedJWT, pOpts.leewayForClaimsValidation)
	if err != nil {
		return nil, err
	}

	err = checkForDuplicates(disclosures)
	if err != nil {
		return nil, fmt.Errorf("check disclosures: %w", err)
	}

	return signedJWT, nil
}

func verifyHolderVerificationJWT(holderJWT *modeljwt.JSONWebToken, pOpts *parseOpts) error {
	err := common.VerifySigningAlg(holderJWT.Headers, pOpts.holderSigningAlgorithm)
	if err != nil {
		return fmt.Errorf("failed to verify holder signing algorithm: %w", err)
	}

	err = common.VerifyJWT(holderJWT, pOpts.leewayForClaimsValidation)
	if err != nil {
		return err
	}

	sdJWTVersion := common.SDJWTVersionV2
	holderVerificationTyp, ok := holderJWT.Headers.Type()
	if ok && holderVerificationTyp == "kb+jwt" {
		sdJWTVersion = common.SDJWTVersionV5
	}

	switch sdJWTVersion {
	case common.SDJWTVersionV5:
		return verifyKeyBindingJWT(holderJWT, pOpts)
	default:
		return verifyHolderBindingJWT(holderJWT, pOpts)
	}
}

func checkForDuplicates(values []string) error {
	var duplicates []string

	valuesMap := make(map[string]bool)

	for _, val := range values {
		if _, ok := valuesMap[val]; !ok {
			valuesMap[val] = true
		} else {
			duplicates = append(duplicates, val)
		}
	}

	if len(duplicates) > 0 {
		return fmt.Errorf("duplicate values found %v", duplicates)
	}

	return nil
}

func runHolderVerification(sdJWT *modeljwt.JSONWebToken, holderVerificationJWT string, pOpts *parseOpts) error {
	if pOpts.holderVerificationRequired && holderVerificationJWT == "" {
		return fmt.Errorf("holder verification is required")
	}

	if holderVerificationJWT == "" {
		return nil
	}

	signatureVerifier, err := getSignatureVerifier(maphelpers.CopyMap(sdJWT.Payload))
	if err != nil {
		return fmt.Errorf("failed to get signature verifier: %w", err)
	}

	holderJWT, _, err := modeljwt.Parse(holderVerificationJWT,
		modeljwt.WithSignatureVerifier(signatureVerifier))
	if err != nil {
		return fmt.Errorf("parse holder verification JWT: %w", err)
	}

	err = verifyHolderVerificationJWT(holderJWT, pOpts)
	if err != nil {
		return fmt.Errorf("verify holder JWT: %w", err)
	}

	return nil
}

func getSignatureVerifier(claims map[string]interface{}) (docjose.SignatureVerifier, error) {
	cnf, err := common.GetCNF(claims)
	if err != nil {
		return nil, err
	}

	signatureVerifier, err := getSignatureVerifierFromCNF(cnf)
	if err != nil {
		return nil, err
	}

	return signatureVerifier, nil
}

func getSignatureVerifierFromCNF(cnf map[string]interface{}) (docjose.SignatureVerifier, error) {
	jwkObj, ok := cnf["jwk"]
	if !ok {
		return nil, fmt.Errorf("jwt must be present in cnf")
	}

	jwkObjBytes, err := json.Marshal(jwkObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal docjwk: %w", err)
	}

	j := docjwk.JWK{}
	err = j.UnmarshalJSON(jwkObjBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal JWK: %w", err)
	}

	signatureVerifier, err := modeljwt.GetVerifier(
		&sigverifier.PublicKey{JWK: &j})
	if err != nil {
		return nil, fmt.Errorf("get verifier from jwk: %w", err)
	}

	return signatureVerifier, nil
}

func getDisclosedClaims(
	disclosures []string,
	signedJWT *modeljwt.JSONWebToken,
	hash crypto.Hash) (map[string]interface{}, error) {
	disclosureClaims, err := common.GetDisclosureClaims(disclosures, hash)
	if err != nil {
		return nil, fmt.Errorf("get disclosure claims: %w", err)
	}

	disclosedClaims, err := common.GetDisclosedClaims(disclosureClaims, maphelpers.CopyMap(signedJWT.Payload))
	if err != nil {
		return nil, fmt.Errorf("get disclosed claims: %w", err)
	}

	return disclosedClaims, nil
}
