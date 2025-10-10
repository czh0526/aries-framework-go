package mediator

import (
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
)

var logger = log.New("aries-framework//route/service")

const (
	Coordination = "coordinatemediation"
)

type getConnectionOpts struct {
	version service.Version
}

type ConnectionOption func(opts *getConnectionOpts)

func ConnectionByVersion(v service.Version) ConnectionOption {
	return func(opts *getConnectionOpts) {
		opts.version = v
	}
}
