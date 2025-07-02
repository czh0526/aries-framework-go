package modlog

import (
	"fmt"
	spilog "github.com/czh0526/aries-framework-go/spi/log"
	builtinlog "log"
	"os"
)

const (
	logLevelFormatter   = "UTC %s-> %s "
	logPrefixFormatter  = " [%s] "
	callerInfoFormatter = "- %s "
)

func NewDefLog(module string) *DefLog {
	logger := builtinlog.New(
		os.Stdout,
		fmt.Sprintf(logPrefixFormatter, module),
		builtinlog.Ldate|builtinlog.Ltime|builtinlog.LUTC,
	)
	return &DefLog{
		logger: logger,
		module: module,
	}
}

type DefLog struct {
	logger *builtinlog.Logger
	module string
}

func (l *DefLog) Panicf(format string, args ...interface{}) {
	l.logf(spilog.CRITICAL, format, args...)
	os.Exit(1)
}

func (l *DefLog) Fatalf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (l *DefLog) Errorf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (l *DefLog) Warnf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (l *DefLog) Infof(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (l *DefLog) Debugf(msg string, args ...interface{}) {
	//TODO implement me
	panic("implement me")
}

func (l *DefLog) logf(level spilog.Level, format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}
