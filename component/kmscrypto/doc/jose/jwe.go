package jose

import "encoding/json"

type RecipientHeaders struct {
	Alg string          `json:"alg,omitempty"`
	APU string          `json:"apu,omitempty"`
	APV string          `json:"apv,omitempty"`
	IV  string          `json:"iv,omitempty"`
	Tag string          `json:"tag,omitempty"`
	KID string          `json:"kid,omitempty"`
	EPK json.RawMessage `json:"epk,omitempty"`
}

type Recipient struct {
	Header       *RecipientHeaders `json:"header,omitempty"`
	EnceyptedKey string            `json:"encrypted_key,omitempty"`
}

type JSONWebEncryption struct {
	ProtectedHeaders   Headers
	OrigProtectedHdrs  string
	UnprotectedHeaders Headers
	Recipients         []*Recipient
	AAD                string
	IV                 string
	Ciphertext         string
	Tag                string
}
