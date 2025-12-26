package verifiable

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	verifiablemodel "github.com/czh0526/aries-framework-go/component/models/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
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

	ValidateCredentialCommandMethod = "ValidateCredential"
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
