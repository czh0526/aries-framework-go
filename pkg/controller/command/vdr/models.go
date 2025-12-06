package vdr

import (
	"encoding/json"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
)

type Document struct {
	DID json.RawMessage `json:"did,omitempty"`
}

type DIDArgs struct {
	Document
	Name string `json:"name,omitempty"`
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

type DIDRecordResult struct {
	Result []*didstore.Record `json:"result,omitempty"`
}
