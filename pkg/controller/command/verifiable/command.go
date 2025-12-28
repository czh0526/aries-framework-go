package verifiable

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	verifiablemodel "github.com/czh0526/aries-framework-go/component/models/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"github.com/czh0526/aries-framework-go/pkg/controller/command/vdr"
	"github.com/czh0526/aries-framework-go/pkg/internal/logutil"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	verifiablestore "github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	pverifiable "github.com/czh0526/aries-framework-go/provider/verifiable"
	"github.com/piprate/json-gold/ld"
	"io"
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
		return nil, fmt.Errorf("new did store: %w", err)
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
				fmt.Sprintf("failed to get did doc from store or vdr: %s", err))
			return command.NewValidationError(SignCredentialErrorCode,
				fmt.Errorf("failed to get did doc from store or vdr: %w", err))
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
