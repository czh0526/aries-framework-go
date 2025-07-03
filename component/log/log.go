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

func (l *Log) Panicf(msg string, args ...interface{}) {
	l.logger().Panicf(msg, args...)
}

func (l *Log) Fatalf(msg string, args ...interface{}) {
	l.logger().Fatalf(msg, args...)
}

func (l *Log) Errorf(msg string, args ...interface{}) {
	l.logger().Errorf(msg, args...)
}

func (l *Log) Warnf(msg string, args ...interface{}) {
	l.logger().Warnf(msg, args...)
}

func (l *Log) Infof(msg string, args ...interface{}) {
	l.logger().Infof(msg, args...)
}

func (l *Log) Debugf(msg string, args ...interface{}) {
	l.logger().Debugf(msg, args...)
}

func New(module string) spilog.Logger {
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
