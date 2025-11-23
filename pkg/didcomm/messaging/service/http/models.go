package http

type httpOverDIDCommMsg struct {
	ID          string `json:"@id"`
	Method      string `json:"method"`
	ResourceURI string `json:"resource-uri,omitempty"`
	Version     string `json:"version"`
	Headers     []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers"`
	BodyB64 string `json:"body,omitempty"`
}
