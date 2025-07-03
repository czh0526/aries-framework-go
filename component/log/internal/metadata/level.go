package metadata

import spilog "github.com/czh0526/aries-framework-go/spi/log"

const (
	defaultLogLevel   = spilog.INFO
	defaultModuleName = ""
)

func newModuleLevels() *moduleLevels {
	return &moduleLevels{
		levels: make(map[string]spilog.Level),
	}
}

type moduleLevels struct {
	levels map[string]spilog.Level
}

func (l *moduleLevels) SetLevel(name string, level spilog.Level) {
	l.levels[name] = level
}

func (l *moduleLevels) GetLevel(name string) spilog.Level {
	level, exists := l.levels[name]
	if !exists {
		level, exists = l.levels[defaultModuleName]
		if !exists {
			return defaultLogLevel
		}
	}

	return level
}

func (l *moduleLevels) IsEnabledFor(module string, level spilog.Level) bool {
	return level <= l.GetLevel(module)
}
