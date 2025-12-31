//go:build ACAPyInterop

package signer

import (
	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
	"time"
)

func wrapTime(t time.Time) *timeutil.TimeWrapper {
	tw, _ := timeutil.ParseTimeWrapper(t.Format(time.RFC3339))
	return tw
}
