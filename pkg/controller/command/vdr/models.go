package vdr

import "encoding/json"

type NameArg struct {
	Name string `json:"name"`
}

type CreateDIDRequest struct {
	Method string                 `json:"method,omitempty"`
	DID    json.RawMessage        `json:"did,omitempty"`
	Opts   map[string]interface{} `json:"opts,omitempty"`
}
