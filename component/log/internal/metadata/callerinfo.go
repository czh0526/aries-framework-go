package metadata

import spilog "github.com/czh0526/aries-framework-go/spi/log"

func newCallerInfo() *callerInfo {
	return &callerInfo{
		info: map[callerInfoKey]bool{
			{"", spilog.CRITICAL}: true,
			{"", spilog.ERROR}:    true,
			{"", spilog.WARNING}:  true,
			{"", spilog.INFO}:     true,
			{"", spilog.DEBUG}:    true,
		},
	}
}

type callerInfoKey struct {
	module string
	level  spilog.Level
}

type callerInfo struct {
	info map[callerInfoKey]bool
}

func (l *callerInfo) IsCallerInfoEnabled(module string, level spilog.Level) bool {
	show, exists := l.info[callerInfoKey{module: module, level: level}]
	if !exists {
		return l.info[callerInfoKey{module: "", level: level}]
	}
	return show
}
