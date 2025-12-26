package verifiable

import (
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	verifiablecmd "github.com/czh0526/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
	"net/http"
)

const (
	VerifiableOperationID      = "/verifiable"
	verifiableCredentialPath   = VerifiableOperationID + "/credential"
	verifiablePresentationPath = VerifiableOperationID + "/presentation"

	ValidateCredentialPath = verifiableCredentialPath + "/validate"
)

type provider interface {
	StorageProvider() spistorage.Provider
	VDRegistry() vdrapi.Registry
	KMS() spikms.KeyManager
	Crypto() spicrypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
}

type Operation struct {
	handlers []rest.Handler
	command  *verifiablecmd.Command
}

func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

func New(p provider) (*Operation, error) {
	cmd, err := verifiablecmd.New(p)
	if err != nil {
		return nil, err
	}

	o := &Operation{
		command: cmd,
	}
	o.registerHandler()

	return o, nil
}

func (o *Operation) registerHandler() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(ValidateCredentialPath, http.MethodPost, o.ValidateCredential),
	}
}

func (o *Operation) ValidateCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ValidateCredential, rw, req.Body)
}
