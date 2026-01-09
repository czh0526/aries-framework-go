package decorator

import (
	"encoding/json"
	"time"
)

const (
	TransportReturnRouteNone = "none"

	TransportReturnRouteAll = "all"

	TransportReturnRouteThread = "thread"
)

type Thread struct {
	ID             string         `json:"thid,omitempty"`
	PID            string         `json:"pthid,omitempty"`
	SenderOrder    int            `json:"sender_order,omitempty"`
	ReceivedOrders map[string]int `json:"received_orders,omitempty"`
}

type Transport struct {
	ReturnRoute *ReturnRoute `json:"~transport,omitempty"`
}

type ReturnRoute struct {
	Value string `json:"~return_route,omitempty"`
}

type Timing struct {
	ExpiresTime time.Time `json:"expires_time,omitempty"`
}

type Attachment struct {
	ID          string         `json:"@id,omitempty"`
	Description string         `json:"description,omitempty"`
	FileName    string         `json:"filename,omitempty"`
	MimeType    string         `json:"mime-type,omitempty"`
	LastModTime time.Time      `json:"lastmod_time,omitempty"`
	ByteCount   int64          `json:"byte_count,omitempty"`
	Data        AttachmentData `json:"data,omitempty"`
}

type AttachmentData struct {
	Sha256 string          `json:"sha256,omitempty"`
	Links  []string        `json:"links,omitempty"`
	Base64 string          `json:"base64,omitempty"`
	JSON   interface{}     `json:"json,omitempty"`
	JWS    json.RawMessage `json:"jws,omitempty"`
}
