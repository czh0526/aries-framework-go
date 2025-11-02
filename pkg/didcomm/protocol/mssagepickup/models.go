package messagepickup

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/decorator"
	"time"
)

type Status struct {
	Type              string            `json:"@type,omitempty"`
	ID                string            `json:"@id,omitempty"`
	MessageCount      int               `json:"message_count"`
	DurationWaited    int               `json:"duration_waited,omitempty"`
	LastAddedTime     time.Time         `json:"last_added_time,omitempty"`
	LastDeliveredTime time.Time         `json:"last_delivered_time,omitempty"`
	LastRemovedTime   time.Time         `json:"last_removed_time,omitempty"`
	TotalSize         int               `json:"total_size,omitempty"`
	Thread            *decorator.Thread `json:"~thread,omitempty"`
}

type Batch struct {
	Type     string            `json:"@type,omitempty"`
	ID       string            `json:"@id,omitempty"`
	Messages []*Message        `json:"messages~attach"`
	Thread   *decorator.Thread `json:"~thread,omitempty"`
}

type Message struct {
	ID        string    `json:"id"`
	AddedTime time.Time `json:"added_time"`
	Message   []byte    `json:"msg,omitempty"`
}
