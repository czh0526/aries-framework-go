package kms

import (
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	cmdkms "github.com/czh0526/aries-framework-go/pkg/controller/command/kms"
	"github.com/czh0526/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"io"
	"net/http"
)

const (
	KmsOperationID   = "/kms"
	CreateKeySetPath = KmsOperationID + "/keyset"
	ImportKeyPath    = KmsOperationID + "/import"
)

type provider interface {
	KMS() spikms.KeyManager
}

type kmsCommand interface {
	CreateKeySet(rw io.Writer, req io.Reader) command.Error
	ImportKey(rw io.Writer, req io.Reader) command.Error
}

var _ kmsCommand = (*cmdkms.Command)(nil)

type Operation struct {
	handlers []rest.Handler
	command  kmsCommand
}

// CreateKeySet swagger:route POST /kms/keyset kms createKeySet
//
// Create key set.
//
// Responses:
//
//	default: genericError
//	    200: createKeySetRes
func (o *Operation) CreateKeySet(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateKeySet, rw, req.Body)
}

// ImportKey swagger:route POST /kms/import kms importKey
//
// Import key.
//
// Responses:
//
//	default: genericError
func (o *Operation) ImportKey(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ImportKey, rw, req.Body)
}

func (o *Operation) registerHandler() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(CreateKeySetPath, http.MethodPost, o.CreateKeySet),
		cmdutil.NewHTTPHandler(ImportKeyPath, http.MethodPost, o.ImportKey),
	}
}

func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

func New(p provider) *Operation {
	cmd := cmdkms.New(p)

	o := &Operation{
		command: cmd,
	}
	o.registerHandler()

	return o
}
