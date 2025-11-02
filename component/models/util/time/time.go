package time

import "time"

type TimeWrapper struct {
	time.Time
	timeStr string
}
