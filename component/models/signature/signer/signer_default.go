//go:build !AVAPyInterop

package signer

import (
	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
	"time"
)

func wrapTime(t time.Time) *timeutil.TimeWrapper {
	return &timeutil.TimeWrapper{Time: t}
}
