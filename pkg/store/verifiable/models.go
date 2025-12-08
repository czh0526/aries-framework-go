package verifiable

type Record struct {
	Name      string   `json:"name,omitempty"`
	ID        string   `json:"id,omitempty"`
	Context   []string `json:"context,omitempty"`
	Type      []string `json:"type,omitempty"`
	SubjectID string   `json:"subjectId,omitempty"`
	MyDID     string   `json:"my_did,omitempty"`
	TheirDID  string   `json:"their_did,omitempty"`
}
