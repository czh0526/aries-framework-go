package verifiable

type CustomFields map[string]interface{}

type TypedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

type Proof map[string]interface{}
