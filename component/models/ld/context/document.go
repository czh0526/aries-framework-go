package context

import "encoding/json"

type Document struct {
	URL         string          `json:"url,omitempty"`
	DocumentURL string          `json:"documentURL,omitempty"`
	Content     json.RawMessage `json:"content,omitempty"`
}
