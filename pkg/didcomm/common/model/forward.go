package model

type Forward struct {
	Type string `json:"@type,omitempty"`
	ID   string `json:"@id,omitempty"`
	To   string `json:"to,omitempty"`
	Msg  []byte `json:"msg,omitempty"`
}
