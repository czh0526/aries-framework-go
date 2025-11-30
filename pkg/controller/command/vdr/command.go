package vdr

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"github.com/czh0526/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/czh0526/aries-framework-go/pkg/internal/logutil"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/gorilla/mux"
	"io"
)

var logger = log.New("aries-framework/command/vdr")

const (
	CommandName = "vdr"

	SaveDIDCommandMethod    = "SaveDID"
	GetDIDsCommandMethod    = "GetDIDRecords"
	GetDIDCommandMethod     = "GetDID"
	ResolveDIDCommandMethod = "ResolveDID"
	CreateDIDCommandMethod  = "CreateDID"

	didID = "did"
)

type provider interface {
	VDRegistry() vdrapi.Registry
	StorageProvider() spistorage.Provider
}

type Command struct {
	ctx      provider
	didStore *didstore.Store
}

func New(p provider) (*Command, error) {
	didStore, err := didstore.New(p)
	if err != nil {
		return nil, fmt.Errorf("new did store: %w", err)
	}

	return &Command{
		ctx:      p,
		didStore: didStore,
	}, nil
}

func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, SaveDIDCommandMethod, o.SaveDID),
		cmdutil.NewCommandHandler(CommandName, GetDIDCommandMethod, o.GetDID),
		cmdutil.NewCommandHandler(CommandName, GetDIDsCommandMethod, o.GetDIDRecords),
		cmdutil.NewCommandHandler(CommandName, ResolveDIDCommandMethod, o.ResolveDID),
		cmdutil.NewCommandHandler(CommandName, CreateDIDCommandMethod, o.CreateDID),
	}
}

func (o *Command) CreateDID(rw io.Writer, req io.Reader) command.Error {
	var request CreateDIDRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("decode request failed: %w", err))
	}

	if request.Method == "" {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, errEmptyDIDMethod)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDMethod))
	}

	didDoc := &did.Doc{}
	if len(request.DID) != 0 {

	}
}
