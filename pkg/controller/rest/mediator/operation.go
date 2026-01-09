package mediator

import (
	medcmd "github.com/czh0526/aries-framework-go/pkg/controller/command/mediator"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	medprovider "github.com/czh0526/aries-framework-go/provider/mediator"
)

type Operation struct {
	handlers []rest.Handler
	command  *medcmd.Command
}

func New(ctx medprovider.Provider, autoAccept bool) (*Operation, error) {
	command, err := medcmd.New(ctx)
	if err != nil {
		return nil, err
	}

	return &Operation{
		command: command,
	}, nil
}
