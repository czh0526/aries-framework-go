package decorator

import "time"

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
