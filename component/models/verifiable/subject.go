package verifiable

type Subject struct {
	ID           string       `json:"id,omitempty"`
	CustomFields CustomFields `json:"-"`
}

func (s *Subject) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (s *Subject) UnmarshalJSON(data []byte) error {
	return nil
}
