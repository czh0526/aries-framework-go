package mediator

import (
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	medclient "github.com/czh0526/aries-framework-go/pkg/client/mediator"
	msgpickupclient "github.com/czh0526/aries-framework-go/pkg/client/messagepickup"
	oobclient "github.com/czh0526/aries-framework-go/pkg/client/outofband"
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/internal/logutil"
	medprovider "github.com/czh0526/aries-framework-go/provider/mediator"
	"io"
)

var logger = log.New("aries-framework/command/route")

// Error codes.
const (
	// InvalidRequestErrorCode for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.ROUTE)

	// ResponseWriteErrorCode for connection ID validation error.
	RegisterMissingConnIDCode

	// RegisterRouterErrorCode for register router error.
	RegisterRouterErrorCode

	// UnregisterRouterErrorCode for unregister router error.
	UnregisterRouterErrorCode

	// GetConnectionsErrorCode for get connections error.
	GetConnectionsErrorCode

	// ReconnectMissingConnIDCode for connection ID validation error.
	ReconnectMissingConnIDCode

	// ReconnectRouterErrorCode for reconnecting router error.
	ReconnectRouterErrorCode

	// StatusRequestMissingConnIDCode for connection ID validation error.
	StatusRequestMissingConnIDCode

	// StatusRequestErrorCode for status request error.
	StatusRequestErrorCode

	// BatchPickupMissingConnIDCode for connection ID validation error.
	BatchPickupMissingConnIDCode

	// BatchPickupRequestErrorCode for batch pick up error.
	BatchPickupRequestErrorCode

	// ReconnectAllError is typically a code for mediator reconnectAll errors.
	ReconnectAllError
)

const (
	CommandName = "mediator"

	RegisterCommandMethod       = "Register"
	UnregisterCommandMethod     = "Unregister"
	GetConnectionsCommandMethod = "Connections"
	ReconnectCommandMethod      = "Reconnect"
	StatusCommandMethod         = "Status"
	BatchPickupCommandMethod    = "BatchPickup"

	connectionID  = "connectionID"
	successString = "success"
)

type Command struct {
	routeClient   *medclient.Client
	messageClient *msgpickupclient.Client
	outOfBand     *oobclient.Client
}

func New(ctx medprovider.Provider, autoAccept bool) (*Command, error) {
	routeClient, err := medclient.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create route client: %w", err)
	}

	if !autoAccept {
		autoAccept = true
	}

	if autoAccept {
		actions := make(chan didcommsvc.DIDCommAction)

		err = routeClient.RegisterActionEvent(actions)
		if err != nil {
			return nil, fmt.Errorf("failed to register action events channel: %w", err)
		}

		go didcommsvc.AutoExecuteActionEvent(actions)
	}

	msgpickupClient, err := msgpickupclient.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create message pickup client: %w", err)
	}

	oobClient, err := oobclient.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create out of band client: %w", err)
	}

	return &Command{
		routeClient:   routeClient,
		messageClient: msgpickupClient,
		outOfBand:     oobClient,
	}, nil
}

func (o *Command) Register(rw io.Writer, req io.Reader) command.Error {
	var request RegisterRoute

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, RegisterCommandMethod, err.Error())
		return command.NewValidationError(
			InvalidRequestErrorCode,
			fmt.Errorf("failed to decode register route request: %w", err))
	}

	if request.ConnectionID == "" {
		logutil.LogDebug(logger, CommandName, RegisterCommandMethod, "connectionID is empty")
		return command.NewValidationError(
			RegisterMissingConnIDCode,
			fmt.Errorf("connectionID is mandatory"))
	}

	err = o.routeClient.Register(request.ConnectionID)
	if err != nil {
		logutil.LogError(logger, CommandName, RegisterCommandMethod, err.Error(),
			logutil.CreateKeyValueString(connectionID, request.ConnectionID))
		return command.NewValidationError(
			RegisterRouterErrorCode,
			fmt.Errorf("failed to register router: %w", err))
	}

	command.WriteNillableResponse(rw, nil, logger)

	logutil.LogDebug(logger, CommandName, RegisterCommandMethod, successString,
		logutil.CreateKeyValueString(connectionID, request.ConnectionID))

	return nil
}
