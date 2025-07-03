package metadata

import spilog "github.com/czh0526/aries-framework-go/spi/log"

var levelNames = []string{
	"CRITICAL",
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG",
}

func ParseString(level spilog.Level) string {
	return levelNames[level]
}
