package outofband

type Invitation struct {
	ID        string        `json:"@id"`
	Type      string        `json:"@type"`
	Label     string        `json:"label,omitempty"`
	Goal      string        `json:"goal,omitempty"`
	GoalCode  string        `json:"goal_code,omitempty"`
	Services  []interface{} `json:"services"`
	Accept    []string      `json:"accept,omitempty"`
	Protocols []string      `json:"handshake_protocols,omitempty"`
}

type Options interface {
	MyLabel() string
	RouterConnections() []string
	ReuseAnyConnection() bool
	ReuseConnection() string
}
