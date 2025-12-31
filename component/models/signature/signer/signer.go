package signer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	ldproofmodel "github.com/czh0526/aries-framework-go/component/models/ld/proof"
	"time"
)

const defaultProofPurpose = "assertionMethod"

type SignatureSuite interface {
	GetCanonicalDocument(doc map[string]interface{}, opts ...ldprocessormodel.Opts) ([]byte, error)

	GetDigest(doc []byte) []byte

	Accept(signatureType string) bool

	Sign(doc []byte) ([]byte, error)

	Alg() string

	CompactProof() bool
}

type DocumentSigner struct {
	signatureSuites []SignatureSuite
}

type Context struct {
	SignatureType           string
	Creator                 string
	SignatureRepresentation ldproofmodel.SignatureRepresentation
	Created                 *time.Time
	Domain                  string
	Nonce                   []byte
	VerificationMethod      string
	Challenge               string
	Purpose                 string
	CapabilityChain         []interface{}
}

func New(signatureSuites ...SignatureSuite) *DocumentSigner {
	return &DocumentSigner{
		signatureSuites: signatureSuites,
	}
}

func (signer *DocumentSigner) Sign(
	context *Context,
	jsonLdDoc []byte,
	opts ...ldprocessormodel.Opts) ([]byte, error) {

	var jsonLdObject map[string]interface{}

	// 反序列化 JSON-LD DID Document
	err := json.Unmarshal(jsonLdDoc, &jsonLdObject)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal json ld document: %w", err)
	}

	// 签名
	err = signer.signObject(context, jsonLdObject, opts)
	if err != nil {
		return nil, err
	}

	// 序列化 JSON-LD DID Document
	signedDoc, err := json.Marshal(jsonLdObject)
	if err != nil {
		return nil, err
	}

	return signedDoc, nil
}

func (signer *DocumentSigner) signObject(
	context *Context,
	jsonLdObject map[string]interface{},
	opts []ldprocessormodel.Opts) error {
	if err := isValidContext(context); err != nil {
		return err
	}

	suite, err := signer.getSignatureSuite(context.SignatureType)
	if err != nil {
		return err
	}

	created := context.Created
	if created == nil {
		now := time.Now()
		created = &now
	}

	p := &ldproofmodel.Proof{
		Type:                    context.SignatureType,
		SignatureRepresentation: context.SignatureRepresentation,
		Creator:                 context.Creator,
		Created:                 wrapTime(*created),
		Domain:                  context.Domain,
		Nonce:                   context.Nonce,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		ProofPurpose:            context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}

	if p.ProofPurpose == "" {
		p.ProofPurpose = defaultProofPurpose
	}

	if context.SignatureRepresentation == ldproofmodel.SignatureJWS {
		p.JWS = ldproofmodel.CreateDetachedJWTHeader(suite.Alg()) + ".."
	}

	message, err := ldproofmodel.CreateVerifyData(
		suite, jsonLdObject, p,
		append(opts, ldprocessormodel.WithValidateRDF())...)
	if err != nil {
		return err
	}

	s, err := suite.Sign(message)
	if err != nil {
		return err
	}

	signer.applySignatureValue(context, p, s)

	return ldproofmodel.AddProof(jsonLdObject, p)
}

func (signer *DocumentSigner) applySignatureValue(context *Context,
	p *ldproofmodel.Proof, s []byte) {
	switch context.SignatureRepresentation {
	case ldproofmodel.SignatureProofValue:
		p.ProofValue = s
	case ldproofmodel.SignatureJWS:
		p.JWS += base64.RawURLEncoding.EncodeToString(s)
	}
}

func (signer *DocumentSigner) getSignatureSuite(signatureType string) (SignatureSuite, error) {
	for _, s := range signer.signatureSuites {
		if s.Accept(signatureType) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("signature type `%s` is not supported", signatureType)
}

func isValidContext(context *Context) error {
	if context.SignatureType == "" {
		return errors.New("signature type is missing")
	}

	return nil
}
