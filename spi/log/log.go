package log

type Level int

const (
	CRITICAL Level = iota
	ERROR
	WARNING
	INFO
	DEBUG
)

type Logger interface {
	Panicf(msg string, args ...interface{})
	Fatalf(msg string, args ...interface{})
	Errorf(msg string, args ...interface{})
	Warnf(msg string, args ...interface{})
	Infof(msg string, args ...interface{})
	Debugf(msg string, args ...interface{})
}

type LoggerProvider interface {
	GetLogger(module string) Logger
}
