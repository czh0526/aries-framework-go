package verifiable

import (
	"encoding/json"
	"fmt"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
)

type Subject struct {
	ID           string       `json:"id,omitempty"`
	CustomFields CustomFields `json:"-"`
}

func (s *Subject) MarshalJSON() ([]byte, error) {
	type Alias Subject
	alias := Alias(*s)

	data, err := jsonutil.MarshalWithCustomFields(alias, s.CustomFields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject: %v", err)
	}

	return data, nil
}

func (s *Subject) UnmarshalJSON(data []byte) error {
	var subjectID string

	if err := json.Unmarshal(data, &subjectID); err != nil {
		s.ID = subjectID
		return nil
	}

	type Alias Subject
	alias := (*Alias)(s)
	s.CustomFields = make(CustomFields)
	err := jsonutil.UnmarshalWithCustomFields(data, alias, s.CustomFields)
	if err != nil {
		return fmt.Errorf("failed to unmarshal subject: %v", err)
	}

	return nil
}
