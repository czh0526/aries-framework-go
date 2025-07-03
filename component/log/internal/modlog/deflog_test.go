package modlog

import (
	"fmt"
	"github.com/stretchr/testify/require"
	builtinlog "log"
	"os"
	"testing"
)

func TestBuiltinLog(t *testing.T) {
	log := builtinlog.New(
		os.Stdout,
		fmt.Sprintf(logPrefixFormatter, "test-module"),
		builtinlog.Ldate|builtinlog.Ltime|builtinlog.LUTC,
	)

	callDepth := 2
	err := log.Output(callDepth, "-> this is a log message")
	require.NoError(t, err)
}

func TestDefLog(t *testing.T) {
	const module = "sample-module"

	defLog := NewDefLog(module)
	defLog.Debugf("this is a `debug` message")
	defLog.Infof("this is a `info` message")
	defLog.Warnf("this is a `warn` message")
	defLog.Errorf("this is a `error` message")
	defLog.Fatalf("this is a `fatal` message")
	defLog.Panicf("this is a `panic` message")
}
