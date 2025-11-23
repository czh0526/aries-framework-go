package logutil

import spilog "github.com/czh0526/aries-framework-go/spi/log"

func LogError(logger spilog.Logger, command, action, errMsg string, data ...string) {
	logger.Errorf("command=[%s] action=[%s] %s errMsg=[%s]", command, action, data, errMsg)
}

func LogDebug(logger spilog.Logger, command, action, msg string, data ...string) {
	logger.Debugf("command=[%s] action=[%s] %s msg=[%s]", command, action, data, msg)
}

func LogInfo(logger spilog.Logger, command, action, msg string, data ...string) {
	logger.Infof("command=[%s] action=[%s] %s msg=[%s]", command, action, data, msg)
}
