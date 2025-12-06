package vdr

import (
	"fmt"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/controller/command/vdr"
	cmdvdr "github.com/czh0526/aries-framework-go/pkg/controller/command/vdr"
	"github.com/czh0526/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"net/http"
)

const (
	VDROperationID    = "/vdr"
	vdrDIDPath        = VDROperationID + "/did"
	SaveDIDPath       = vdrDIDPath
	GetDIDPath        = vdrDIDPath + "/{id}"
	ResolveDIDPath    = vdrDIDPath + "/resolve"
	CreateDIDPath     = vdrDIDPath + "/create"
	GetDIDRecordsPath = vdrDIDPath + "/records"
)

type provider interface {
	VDRegistry() vdrapi.Registry
	StorageProvider() spistorage.Provider
}

type Operation struct {
	handlers []rest.Handler
	command  *vdr.Command
}

func New(p provider) (*Operation, error) {
	cmd, err := cmdvdr.New(p)
	if err != nil {
		return nil, fmt.Errorf("new vdr: %w", err)
	}

	o := &Operation{
		command: cmd,
	}
	o.registerHandler()

	return o, nil
}

func (o *Operation) registerHandler() {
	o.handlers = []rest.Handler{
		cmdutil.NewHTTPHandler(SaveDIDPath, http.MethodPost, o.SaveDID),
		cmdutil.NewHTTPHandler(ResolveDIDPath, http.MethodGet, o.ResolveDID),
		cmdutil.NewHTTPHandler(CreateDIDPath, http.MethodPost, o.CreateDID),
		cmdutil.NewHTTPHandler(GetDIDRecordsPath, http.MethodGet, o.GetDIDRecords),
		cmdutil.NewHTTPHandler(GetDIDPath, http.MethodGet, o.GetDID),
	}
}

func (o *Operation) CreateDID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateDID, rw, req.Body)
}

func (o *Operation) ResolveDID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.ResolveDID, rw, req.Body)
}

func (o *Operation) SaveDID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.SaveDID, rw, req.Body)
}

func (o *Operation) GetDIDRecords(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetDIDRecords, rw, req.Body)
}

func (o *Operation) GetDID(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetDID, rw, req.Body)
}

func (o *Operation) GetRESETHandlers() []rest.Handler {
	return o.handlers
}
