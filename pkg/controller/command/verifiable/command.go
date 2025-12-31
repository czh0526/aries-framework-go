package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmssigner"
	"github.com/czh0526/aries-framework-go/component/log"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	ldprocessormodel "github.com/czh0526/aries-framework-go/component/models/ld/processor"
	signermodel "github.com/czh0526/aries-framework-go/component/models/signature/signer"
	sigsuite "github.com/czh0526/aries-framework-go/component/models/signature/suite"
	verifiablemodel "github.com/czh0526/aries-framework-go/component/models/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"github.com/czh0526/aries-framework-go/pkg/controller/command/vdr"
	"github.com/czh0526/aries-framework-go/pkg/internal/logutil"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	verifiablestore "github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	pverifiable "github.com/czh0526/aries-framework-go/provider/verifiable"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/piprate/json-gold/ld"
	"io"
	"strings"
)

var logger = log.New("aries-framework/command/verifiable")

const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VC)

	// ValidateCredentialErrorCode for validate vc error.
	ValidateCredentialErrorCode

	// SaveCredentialErrorCode for save vc error.
	SaveCredentialErrorCode

	// GetCredentialErrorCode for get vc error.
	GetCredentialErrorCode

	// GetCredentialByNameErrorCode for get vc by name error.
	GetCredentialByNameErrorCode

	// GeneratePresentationErrorCode for get generate vp error.
	GeneratePresentationErrorCode

	// GeneratePresentationByIDErrorCode for get generate vp by vc id error.
	GeneratePresentationByIDErrorCode

	// SavePresentationErrorCode for save presentation error.
	SavePresentationErrorCode

	// GetPresentationErrorCode for get vp error.
	GetPresentationErrorCode

	// GetCredentialsErrorCode for get credential records.
	GetCredentialsErrorCode

	// GetPresentationsErrorCode for get presentation records.
	GetPresentationsErrorCode

	// SignCredentialErrorCode for sign credential error.
	SignCredentialErrorCode

	// RemoveCredentialByNameErrorCode for remove vc by name errors.
	RemoveCredentialByNameErrorCode

	// RemovePresentationByNameErrorCode for remove vp by name errors.
	RemovePresentationByNameErrorCode

	// DeriveCredentialErrorCode for derive credential error.
	DeriveCredentialErrorCode
)

const (
	CommandName = "verifiable"

	ValidateCredentialCommandMethod  = "ValidateCredential"
	SaveCredentialCommandMethod      = "SaveCredential"
	GetCredentialCommandMethod       = "GetCredential"
	GetCredentialByNameCommandMethod = "GetCredentialByName"
	SignCredentialCommandMethod      = "SignCredential"

	errEmptyCredentialName   = "credential name is mandatory"
	errEmptyPresentationName = "presentation name is mandatory"
	errEmptyCredentialID     = "credential is is mandatory"

	vcID   = "vcID"
	vcName = "vcName"
	vpID   = "vpID"
)

const (
	Ed25519VerificationKey = "Ed25519VerificationKey"
	JSONWebKey2020         = "JSONWebKey2020"

	// Ed25519Signature2018 ed25519 signature suite.
	Ed25519Signature2018 = "Ed25519Signature2018"
	// JSONWebSignature2020 json web signature suite.
	JSONWebSignature2020 = "JsonWebSignature2020"

	// BbsBlsSignature2020 BBS signature suite.
	BbsBlsSignature2020 = "BbsBlsSignature2020"

	// Ed25519Curve ed25519 curve.
	Ed25519Curve = "Ed25519"

	// P256KeyCurve EC P-256 curve.
	P256KeyCurve = "P-256"

	// P384KeyCurve EC P-384 curve.
	P384KeyCurve = "P-384"

	// P521KeyCurve EC P-521 curve.
	P521KeyCurve = "P-521"

	p256Alg = "ES256"
	p384Alg = "ES384"
	p521Alg = "ES521"
	edAlg   = "EdDSA"
)

type provable interface {
	AddLinkedDataProof(context *verifiablemodel.LinkedDataProofContext, jsonldOpts ...ldprocessormodel.Opts) error
}

var _ provable = (*verifiablemodel.Credential)(nil)

type keyResolver interface {
	PublicKeyFetcher() didsignjwt.PublicKeyFetcher
}

var _ keyResolver = (*verifiablemodel.VDRKeyResolver)(nil)

type Command struct {
	verifiableStore verifiablestore.Store
	didStore        *didstore.Store
	resolver        keyResolver
	ctx             pverifiable.Provider
	documentLoader  ld.DocumentLoader
}

func New(p pverifiable.Provider) (*Command, error) {
	verifiableStore, err := verifiablestore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vc store: %w", err)
	}

	didStore, err := didstore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new didmodel store: %w", err)
	}

	return &Command{
		verifiableStore: verifiableStore,
		didStore:        didStore,
		resolver:        verifiablemodel.NewVDRKeyResolver(p.VDRegistry()),
		ctx:             p,
		documentLoader:  p.JSONLDDocumentLoader(),
	}, nil
}

func (c *Command) ValidateCredential(rw io.Writer, req io.Reader) command.Error {
	request := &Credential{}

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ValidateCredentialCommandMethod,
			fmt.Sprintf("request decode: %w", err))

		return command.NewValidationError(InvalidRequestErrorCode,
			fmt.Errorf("request decode: %w", err))
	}

	_, err = verifiablemodel.ParseCredential([]byte(request.VerifiableCredential),
		verifiablemodel.WithPublicKeyFetcher(c.resolver.PublicKeyFetcher()),
		verifiablemodel.WithJSONLDDocumentLoader(c.documentLoader))
	if err != nil {
		logutil.LogInfo(logger, CommandName, ValidateCredentialCommandMethod,
			fmt.Sprintf("validate vc failed, err = %w", err))

		return command.NewValidationError(ValidateCredentialErrorCode,
			fmt.Errorf("validate vc failed, err = %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogInfo(logger, CommandName, ValidateCredentialCommandMethod, "validate vc success")

	return nil
}

func (o *Command) SaveCredential(rw io.Writer, req io.Reader) command.Error {
	request := &CredentialExt{}

	err := json.NewDecoder(req).Decode(request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SaveCredentialCommandMethod, fmt.Sprintf("request decode: %s", err))
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode: %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, SaveCredentialCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	vc, err := verifiablemodel.ParseCredential([]byte(request.VerifiableCredential),
		verifiablemodel.WithDisabledProofCheck(),
		verifiablemodel.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		logutil.LogError(logger, CommandName, vdr.SaveDIDCommandMethod, fmt.Sprintf("parse vc: %s", err))
		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("parse vc: %w", err))
	}

	err = o.verifiableStore.SaveCredential(request.Name, vc)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveCredentialCommandMethod, fmt.Sprintf("save vc: %s", err))
		return command.NewValidationError(SaveCredentialErrorCode, fmt.Errorf("save vc: %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, SaveCredentialCommandMethod, "save vc success")

	return nil
}

func (o *Command) GetCredential(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetCredentialCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode: %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, GetCredentialCommandMethod, errEmptyCredentialID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialID))
	}

	vc, err := o.verifiableStore.GetCredential(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialCommandMethod, fmt.Sprintf("get vc: %s", err),
			logutil.CreateKeyValueString(vcID, request.ID))
		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("get vc: %w", err))
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialCommandMethod, fmt.Sprintf("marshal vc: %s", err),
			logutil.CreateKeyValueString(vcID, request.ID))
		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("marshal vc: %w", err))
	}

	command.WriteNillableResponse(rw, &Credential{
		VerifiableCredential: string(vcBytes),
	}, logger)

	logutil.LogDebug(logger, CommandName, GetCredentialCommandMethod, "get vc success",
		logutil.CreateKeyValueString(vcID, request.ID))

	return nil
}

func (o *Command) GetCredentialByName(rw io.Writer, req io.Reader) command.Error {
	var request NameArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetCredentialCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode: %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, GetCredentialByNameCommandMethod, errEmptyCredentialName)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyCredentialName))
	}

	id, err := o.verifiableStore.GetCredentialIDByName(request.Name)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialCommandMethod, fmt.Sprintf("get vc by name: %s", err),
			logutil.CreateKeyValueString(vcName, request.Name))
		return command.NewValidationError(GetCredentialByNameErrorCode, fmt.Errorf("get vc by name: %w", err))
	}

	command.WriteNillableResponse(rw, &verifiablestore.Record{
		Name: request.Name,
		ID:   id,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetCredentialCommandMethod, "get vc by name success",
		logutil.CreateKeyValueString(vcName, request.Name))

	return nil
}

func (o *Command) GetCredentials(rw io.Writer, req io.Reader) command.Error {
	vcRecords, err := o.verifiableStore.GetCredentials()
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredentialCommandMethod,
			fmt.Sprintf("get credential records : %s", err))
		return command.NewValidationError(GetCredentialErrorCode, fmt.Errorf("get credential records: %w", err))
	}

	command.WriteNillableResponse(rw, &RecordResult{
		Result: vcRecords,
	}, logger)

	logutil.LogDebug(logger, CommandName, GetCredentialCommandMethod, "get vc success")

	return nil
}

func (o *Command) SignCredential(rw io.Writer, req io.Reader) command.Error {
	request := &SignCredentialRequest{}

	err := json.NewDecoder(req).Decode(request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, SignCredentialCommandMethod, fmt.Sprint("request decode: ", err))
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode: %w", err))
	}

	didDoc, err := o.didStore.GetDID(request.DID)
	if err != nil {
		doc, resolveErr := o.ctx.VDRegistry().Resolve(request.DID)
		if resolveErr != nil {
			logutil.LogError(logger, CommandName, SignCredentialCommandMethod,
				fmt.Sprintf("failed to get didmodel doc from store or vdr: %s", err))
			return command.NewValidationError(SignCredentialErrorCode,
				fmt.Errorf("failed to get didmodel doc from store or vdr: %w", err))
		}
		didDoc = doc.DIDDocument
	}

	vc, err := verifiablemodel.ParseCredential(request.Credential,
		verifiablemodel.WithDisabledProofCheck(),
		verifiablemodel.WithJSONLDDocumentLoader(o.documentLoader))
	if err != nil {
		logutil.LogError(logger, CommandName, SignCredentialCommandMethod,
			fmt.Sprintf("parse credential: %s", err))
		return command.NewValidationError(SignCredentialErrorCode,
			fmt.Errorf("parse credential: %w", err))
	}

	err = o.addCredentialProof(vc, didDoc, request.ProofOptions)
	if err != nil {
		logutil.LogError(logger, CommandName, SignCredentialCommandMethod,
			fmt.Sprintf("sign credential: %s", err))
		return command.NewValidationError(SignCredentialErrorCode,
			fmt.Errorf("sign credential: %w", err))
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		logutil.LogError(logger, CommandName, SignCredentialCommandMethod,
			fmt.Sprintf("marshal credential: %s", err))
		return command.NewValidationError(SignCredentialErrorCode,
			fmt.Errorf("marshal credential: %w", err))
	}

	command.WriteNillableResponse(rw, &SignCredentialResponse{
		VerifiableCredential: vcBytes,
	}, logger)

	logutil.LogDebug(logger, CommandName, SignCredentialCommandMethod, "get vc success")

	return nil
}

func (o *Command) addCredentialProof(vc *verifiablemodel.Credential, didDoc *didmodel.Doc, opts *ProofOptions) error {
	var err error

	opts, err = prepareOpts(opts, didDoc, didmodel.AssertionMethod)
	if err != nil {
		return err
	}

	return o.addLinkedDataProof(vc, opts)
}

func (o *Command) addLinkedDataProof(p provable, opts *ProofOptions) error {
	s, err := newKMSSigner(o.ctx.KMS(), o.ctx.Crypto(), getKID(opts))
	if err != nil {
		return err
	}

	var signatureSuite signermodel.SignatureSuite

	switch opts.SignatureType {
	case Ed25519Signature2018:
		signatureSuite = ed25519signature2018.New(sigsuite.WithSigner(s))
	case JSONWebSignature2020:
		signatureSuite = jsonwebsignature2020.New(sigsuite.WithSigner(s))
	case BbsBlsSignature2020:
		signatureSuite = bbsblssignature2020.New(sigsuite.WithSigner(s))
	default:
		return fmt.Errorf("signature type unsupported %s", opts.SignatureType)
	}

	return p.AddLinkedDataProof(opts, signatureSuite)
}

func newKMSSigner(keyManager spikms.KeyManager, c spicrypto.Crypto, kid string) (
	*kmssigner.KMSSigner, error) {
	keyHandler, err := keyManager.Get(kid)
	if err != nil {
		return nil, err
	}

	_, kt, err := keyManager.ExportPubKeyBytes(kid)
	if err != nil {
		return nil, err
	}
	return &kmssigner.KMSSigner{
		KeyHandle: keyHandler,
		Crypto:    c,
		KeyType:   kt,
	}, nil
}

func prepareOpts(opts *ProofOptions, didDoc *didmodel.Doc,
	method didmodel.VerificationRelationship) (*ProofOptions, error) {

	if opts == nil {
		opts = &ProofOptions{}
	}

	var err error

	opts.proofPurpose, err = getProofPurpose(method)
	if err != nil {
		return nil, err
	}

	vmType := ""
	switch opts.SignatureType {
	case "Ed25519Signature2018":
		vmType = "Ed25519Signature2018"
	case "BbsBlsSignature2020":
		vmType = "Bls12381G2Key12020"
	}

	vMs := didDoc.VerificationMethods(method)[method]
	vmMatched := opts.VerificationMethod == ""

	for _, vm := range vMs {
		if opts.VerificationMethod != "" {
			// 如果指定了 verificationMethod, 匹配指定的 verificationMethod
			if opts.VerificationMethod == vm.VerificationMethod.ID {
				vmMatched = true
				break
			}

			continue

		} else {
			// 如果没有指定 verificationMethod, 取第一个 Authentication 公钥
			if vmType != "" && vm.VerificationMethod.Type != vmType {
				continue
			}

			opts.VerificationMethod = vm.VerificationMethod.ID
			break
		}
	}

	if !vmMatched {
		return nil, fmt.Errorf("unable to find matching `%s` key IDs for given verification method",
			opts.VerificationMethod)
	}

	if opts.VerificationMethod == "" {
		logger.Warnf("Could not find matching verification method for `%s` proof purpose", opts.proofPurpose)

		var defaultVM string
		defaultVM, err = getDefaultVerificationMethod(didDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to get default verification method: %w", err)
		}

		opts.VerificationMethod = defaultVM
	}

	if strings.Index(opts.VerificationMethod, "#key-") > 0 {
		err = buildKIDOption(opts, didDoc.VerificationMethod)
		if err != nil {
			return nil, fmt.Errorf("build KMS KID error: %w", err)
		}
	}

	return opts, nil
}

func buildKIDOption(opts *ProofOptions, vms []didmodel.VerificationMethod) error {
	for _, vm := range vms {
		if opts.VerificationMethod == vm.ID {
			if len(vm.Value) > 0 {
				kt := spikms.ED25519Type

				switch vm.Type {
				case Ed25519VerificationKey:
				case JSONWebKey2020:
					kt = kmsKeyTypeByJWKCurve(vm.JSONWebKey().Crv)
				}

				kid, err := jwkkid.CreateKID(vm.Value, kt)
				if err != nil {
					return fmt.Errorf("failed to get default verification method: %w", err)
				}

				opts.KID = kid
			}
		}
	}

	return nil
}

func kmsKeyTypeByJWKCurve(crv string) spikms.KeyType {
	kt := spikms.ED25519Type

	switch crv {
	case Ed25519Curve:
	case P256KeyCurve:
		kt = spikms.ECDSAP256TypeIEEEP1363
	case P384KeyCurve:
		kt = spikms.ECDSAP384TypeIEEEP1363
	case P521KeyCurve:
		kt = spikms.ECDSAP521IEEEP1363
	}

	return kt
}

func getDefaultVerificationMethod(didDoc *didmodel.Doc) (string, error) {
	switch {
	case len(didDoc.VerificationMethod) > 0:
		var publicKeyID string

		for _, k := range didDoc.VerificationMethod {
			if strings.HasSuffix(k.ID, Ed25519VerificationKey) {
				publicKeyID = k.ID
				break
			}
		}

		if publicKeyID == "" {
			publicKeyID = didDoc.VerificationMethod[0].ID
		}

		if !isDID(publicKeyID) {
			return didDoc.ID + publicKeyID, nil
		}

		return publicKeyID, nil

	case len(didDoc.Authentication) > 0:
		return didDoc.Authentication[0].VerificationMethod.ID, nil
	default:
		return "", errors.New("public key not found in DID Document")
	}
}

func isDID(str string) bool {
	return strings.HasPrefix(str, "did:")
}

func getProofPurpose(method didmodel.VerificationRelationship) (string, error) {
	if method != didmodel.Authentication && method != didmodel.AssertionMethod {
		return "", fmt.Errorf("unsupported proof purpose, only authentication or assertionMethod are supported")
	}

	if method == didmodel.Authentication {
		return "authentication", nil
	}

	return "assertionMethod", nil
}
