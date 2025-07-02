package modlog

import (
	spilog "github.com/czh0526/aries-framework-go/spi/log"
)

func NewModLog(logger spilog.Logger, module string) *ModLog {
	return &ModLog{
		logger: logger,
		module: module,
	}
}

type ModLog struct {
	logger spilog.Logger
	module string
}

func (m ModLog) Panicf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (m ModLog) Fatalf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (m ModLog) Errorf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (m ModLog) Warnf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (m ModLog) Infof(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (m ModLog) Debugf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}
