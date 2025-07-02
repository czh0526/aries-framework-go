package log

import (
	"github.com/czh0526/aries-framework-go/component/log/internal/modlog"
	spilog "github.com/czh0526/aries-framework-go/spi/log"
	"sync"
)

var (
	loggerProviderInstance spilog.LoggerProvider
	loggerProviderOnce     sync.Once
)

func Initialize(l spilog.LoggerProvider) {
	loggerProviderOnce.Do(func() {
		loggerProviderInstance = &modlogProvider{l}
	})
}

type modlogProvider struct {
	custom spilog.LoggerProvider
}

func (p *modlogProvider) GetLogger(module string) spilog.Logger {
	var logger spilog.Logger
	if p.custom != nil {
		logger = p.custom.GetLogger(module)
	} else {
		logger = modlog.NewDefLog(module)
	}

	return modlog.NewModLog(logger, module)
}
