package modlog

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log/internal/metadata"
	spilog "github.com/czh0526/aries-framework-go/spi/log"
	builtinlog "log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// DefLog means Default Log implement
type DefLog struct {
	logger *builtinlog.Logger
	module string
}

func (l *DefLog) Panicf(format string, args ...interface{}) {
	l.logf(spilog.CRITICAL, format, args...)
	panic(fmt.Sprintf(format, args...))
}

func (l *DefLog) Fatalf(format string, args ...interface{}) {
	l.logf(spilog.CRITICAL, format, args...)
	os.Exit(1)
}

func (l *DefLog) Errorf(format string, args ...interface{}) {
	l.logf(spilog.ERROR, format, args...)
}

func (l *DefLog) Warnf(format string, args ...interface{}) {
	l.logf(spilog.WARNING, format, args...)
}

func (l *DefLog) Infof(format string, args ...interface{}) {
	l.logf(spilog.INFO, format, args...)
}

func (l *DefLog) Debugf(format string, args ...interface{}) {
	l.logf(spilog.DEBUG, format, args...)
}

func (l *DefLog) logf(level spilog.Level, format string, args ...interface{}) {
	const callDepth = 2

	customPrefix := fmt.Sprintf(logLevelFormatter, l.getCallerInfo(level), metadata.ParseString(level))

	err := l.logger.Output(callDepth, customPrefix+fmt.Sprintf(format, args...))
	if err != nil {
		fmt.Printf("error from logger.Output %v\n", err)
	}
}

func (l *DefLog) getCallerInfo(level spilog.Level) string {
	if !metadata.IsCallerInfoEnabled(l.module, level) {
		return ""
	}

	const (
		// search MAXCALLERS caller frames for the real caller,
		// MAXCALLERS defines maximum number of caller frames needed to be recorded to find the actual caller frame
		MAXCALLERS = 6
		// skip SKIPCALLERS frames when determining the real caller
		// SKIPCALLERS is the number of stack frames to skip before recording caller frames,
		// this is mainly used to filter logger library functions in caller frames
		SKIPCALLERS      = 5
		NOTFOUND         = "n/a"
		DEFAULTLOGPREFIX = "log.(*Log)"
	)

	fpcs := make([]uintptr, MAXCALLERS)

	n := runtime.Callers(SKIPCALLERS, fpcs)
	if n == 0 {
		return fmt.Sprintf(callerInfoFormatter, NOTFOUND)
	}

	frames := runtime.CallersFrames(fpcs[:n])
	loggerFrameFound := false

	for f, more := frames.Next(); more; f, more = frames.Next() {
		_, fnName := filepath.Split(f.Function)

		if f.Func == nil || f.Function == "" {
			fnName = NOTFOUND // not a function or unknown
		}

		if loggerFrameFound {
			return fmt.Sprintf(callerInfoFormatter, fnName)
		}

		if strings.HasPrefix(fnName, DEFAULTLOGPREFIX) {
			loggerFrameFound = true

			continue
		}

		return fmt.Sprintf(callerInfoFormatter, fnName)
	}

	return fmt.Sprintf(callerInfoFormatter, NOTFOUND)
}
