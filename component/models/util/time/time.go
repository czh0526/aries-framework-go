package time

import "time"

type TimeWrapper struct {
	time.Time
	timeStr string
}

func (tm *TimeWrapper) parse(timeStr string) error {
	t, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return err
	}

	tm.Time = t
	tm.timeStr = timeStr
	return nil
}

func (tm *TimeWrapper) FormatToString() string {
	if tm.timeStr != "" {
		return tm.timeStr
	}
	
	return tm.Time.Format(time.RFC3339)
}

func ParseTimeWrapper(timeStr string) (*TimeWrapper, error) {
	tm := TimeWrapper{}

	err := tm.parse(timeStr)
	if err != nil {
		return nil, err
	}

	return &tm, nil
}
