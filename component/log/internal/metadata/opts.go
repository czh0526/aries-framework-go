package metadata

import (
	spilog "github.com/czh0526/aries-framework-go/spi/log"
	"sync"
)

var (
	rwmutex     = &sync.RWMutex{}
	levels      = newModuleLevels()
	callerInfos = newCallerInfo()
)

func IsCallerInfoEnabled(module string, level spilog.Level) bool {
	rwmutex.RLock()
	defer rwmutex.RUnlock()

	return callerInfos.IsCallerInfoEnabled(module, level)
}
