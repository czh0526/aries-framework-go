package verifiable

import (
	"bytes"
	"encoding/base64"
	"fmt"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	verifiablecmd "github.com/czh0526/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/gorilla/mux"
	"github.com/piprate/json-gold/ld"
	"net/http"
)

const (
	VerifiableOperationID      = "/verifiable"
	verifiableCredentialPath   = VerifiableOperationID + "/credential"
	verifiablePresentationPath = VerifiableOperationID + "/presentation"

	ValidateCredentialPath  = verifiableCredentialPath + "/validate"
	SaveCredentialPath      = verifiableCredentialPath
	GetCredentialPath       = verifiableCredentialPath + "/{id}"
	GetCredentialByNamePath = verifiableCredentialPath + "/name/{name}"
	GetCredentialsPath      = VerifiableOperationID + "/credentials"
	SignCredentialsPath     = VerifiableOperationID + "/signcredential"
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
		cmdutil.NewHTTPHandler(SaveCredentialPath, http.MethodPost, o.SaveCredential),
		cmdutil.NewHTTPHandler(GetCredentialPath, http.MethodGet, o.GetCredential),
		cmdutil.NewHTTPHandler(GetCredentialByNamePath, http.MethodGet, o.GetCredentialByName),
		cmdutil.NewHTTPHandler(GetCredentialsPath, http.MethodGet, o.GetCredentials),
		cmdutil.NewHTTPHandler(SignCredentialsPath, http.MethodPost, o.SignCredential),
	}
}

func (o *Operation) ValidateCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ValidateCredential, rw, req.Body)
}

func (o *Operation) SaveCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SaveCredential, rw, req.Body)
}

func (o *Operation) GetCredential(rw http.ResponseWriter, req *http.Request) {
	id := mux.Vars(req)["id"]

	decodedID, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		rest.SendHTTPStatusError(rw, http.StatusBadRequest, verifiablecmd.InvalidRequestErrorCode, err)
		return
	}

	request := fmt.Sprintf(`{"id":"%s"}`, string(decodedID))
	rest.Execute(o.command.GetCredential, rw, bytes.NewBufferString(request))
}

func (o *Operation) GetCredentialByName(rw http.ResponseWriter, req *http.Request) {
	name := mux.Vars(req)["name"]

	request := fmt.Sprintf(`{"name":"%s"}`, name)

	rest.Execute(o.command.GetCredentialByName, rw, bytes.NewBufferString(request))
}

func (o *Operation) GetCredentials(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetCredentials, rw, req.Body)
}

func (o *Operation) SignCredential(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SignCredential, rw, req.Body)
}
