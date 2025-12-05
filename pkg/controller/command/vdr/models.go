package vdr

import "encoding/json"

type Document struct {
	DID json.RawMessage `json:"did,omitempty"`
}

type IDArg struct {
	ID string `json:"id"`
}

type NameArg struct {
	Name string `json:"name"`
}

type CreateDIDRequest struct {
	Method string                 `json:"method,omitempty"`
	DID    json.RawMessage        `json:"did,omitempty"`
	Opts   map[string]interface{} `json:"opts,omitempty"`
}
