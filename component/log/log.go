package log

import (
	spilog "github.com/czh0526/aries-framework-go/spi/log"
	"sync"
)

const (
	loggerNotInitializedMsg = "Default logger initialized (please call log.Initialize() if you wish to use a custom logger)"
	loggerModule            = "aries-framework/common"
)

type Log struct {
	instance spilog.Logger
	module   string
	once     sync.Once
}

func New(module string) *Log {
	return &Log{
		module: module,
	}
}

func (l *Log) logger() spilog.Logger {
	l.once.Do(func() {
		l.instance = loggerProvider().GetLogger(l.module)
	})
	return l.instance
}
