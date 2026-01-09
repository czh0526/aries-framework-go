package mediator

import (
	"fmt"
	medclient "github.com/czh0526/aries-framework-go/pkg/client/mediator"
	oobclient "github.com/czh0526/aries-framework-go/pkg/client/outofband"
	didcommsvc "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	medprovider "github.com/czh0526/aries-framework-go/provider/mediator"
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
}
