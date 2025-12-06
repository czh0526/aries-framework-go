package vdr

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"github.com/czh0526/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/czh0526/aries-framework-go/pkg/internal/logutil"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"io"
)

var logger = log.New("aries-framework/command/vdr")

const (
	InvalidRequestErrorCode = command.Code(iota + command.VDR)
	SaveDIDErrorCode
	GetDIDErrorCode
	ResolveDIDErrorCode
	CreateDIDErrorCode
)

const (
	CommandName = "vdr"

	SaveDIDCommandMethod    = "SaveDID"
	GetDIDsCommandMethod    = "GetDIDRecords"
	GetDIDCommandMethod     = "GetDID"
	ResolveDIDCommandMethod = "ResolveDID"
	CreateDIDCommandMethod  = "CreateDID"

	errEmptyDIDName   = "did name is mandatory"
	errEmptyDIDID     = "did id is mandatory"
	errEmptyDIDMethod = "did method is mandatory"

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

	didDoc := &didmodel.Doc{}
	if len(request.DID) != 0 {
		didDoc, err = didmodel.ParseDocument(request.DID)
		if err != nil {
			logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "parse did doc: "+err.Error())
			return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("parse did doc: %w", err))
		}
	}

	opts := make([]spivdr.DIDMethodOption, 0)
	for k, v := range request.Opts {
		opts = append(opts, spivdr.WithOption(k, v))
	}

	doc, err := o.ctx.VDRegistry().Create(request.Method, didDoc, opts...)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "create did doc: "+err.Error())
		return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("create did doc: %w", err))
	}

	docBytes, err := doc.DIDDocument.JSONBytes()
	if err != nil {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "unmarshal did doc: "+err.Error())
		return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	}

	command.WriteNillableResponse(rw, &Document{
		DID: docBytes,
	}, logger)
	logutil.LogDebug(logger, CommandName, CreateDIDCommandMethod, "success")

	return nil
}

func (o *Command) ResolveDID(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, ResolveDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("decode request failed: %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, ResolveDIDCommandMethod, errEmptyDIDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDID))
	}

	doc, err := o.ctx.VDRegistry().Resolve(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, ResolveDIDCommandMethod, "resolve did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))
		return command.NewValidationError(ResolveDIDErrorCode, fmt.Errorf("resolve did doc: %w", err))
	}

	docBytes, err := doc.JSONBytes()

	_, err = rw.Write(docBytes)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("write response: %w", err))
	}

	_, err = rw.Write(docBytes)
	if err != nil {
		logger.Errorf("Unable to send error response: %w", err)
	}

	logutil.LogDebug(logger, CommandName, ResolveDIDCommandMethod, "success",
		logutil.CreateKeyValueString(didID, request.ID))

	return nil
}

func (o *Command) SaveDID(rw io.Writer, req io.Reader) command.Error {
	request := &DIDArgs{}

	err := json.NewDecoder(req).Decode(request)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveDIDCommandMethod, "decode request failed: "+err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("decode request failed: %w", err))
	}

	if request.Name == "" {
		logutil.LogDebug(logger, CommandName, SaveDIDCommandMethod, errEmptyDIDName)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDName))
	}

	didDoc, err := didmodel.ParseDocument(request.DID)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveDIDCommandMethod, "parse did doc: "+err.Error())
		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf("parse did doc: %w", err))
	}

	err = o.didStore.SaveDID(request.Name, didDoc)
	if err != nil {
		logutil.LogError(logger, CommandName, SaveDIDCommandMethod, "save did doc failed: "+err.Error())
		return command.NewValidationError(SaveDIDErrorCode, fmt.Errorf("save did doc: %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)
	logutil.LogDebug(logger, CommandName, SaveDIDCommandMethod, "success")

	return nil
}

func (o *Command) GetDID(rw io.Writer, req io.Reader) command.Error {
	var request IDArg

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogError(logger, CommandName, GetDIDCommandMethod, "decode request failed: "+err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("decode request failed: %w", err))
	}

	if request.ID == "" {
		logutil.LogDebug(logger, CommandName, GetDIDCommandMethod, errEmptyDIDID)
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errEmptyDIDID))
	}

	didDoc, err := o.didStore.GetDID(request.ID)
	if err != nil {
		logutil.LogError(logger, CommandName, GetDIDCommandMethod, "get did doc failed: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))
		return command.NewValidationError(GetDIDErrorCode, fmt.Errorf("get did doc: %w", err))
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		logutil.LogError(logger, CommandName, GetDIDCommandMethod, "unmarshal did doc: "+err.Error(),
			logutil.CreateKeyValueString(didID, request.ID))
		return command.NewValidationError(GetDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	}

	command.WriteNillableResponse(rw, &Document{
		DID: docBytes,
	}, logger)
	logutil.LogDebug(logger, CommandName, GetDIDCommandMethod, "success")

	return nil
}

func (o *Command) GetDIDRecords(rw io.Writer, req io.Reader) command.Error {
	didRecords := o.didStore.GetDIDRecords()

	command.WriteNillableResponse(rw, &DIDRecordResult{
		Result: didRecords,
	}, logger)
	logutil.LogDebug(logger, CommandName, GetDIDCommandMethod, "success")

	return nil
}
