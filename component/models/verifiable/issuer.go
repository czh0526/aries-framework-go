package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
)

type Issuer struct {
	ID           string       `json:"id,omitempty"`
	CustomFields CustomFields `json:"-"`
}

func (i *Issuer) MarshalJSON() ([]byte, error) {
	if len(i.CustomFields) == 0 {
		return json.Marshal(i.ID)
	}

	type Alias Issuer
	alias := Alias(*i)
	fmt.Printf("i = %p, i.CustomFields = %p, alias = %p, alias.CustomFields = %p\n",
		i, i.CustomFields, &alias, alias.CustomFields)
	data, err := jsonutil.MarshalWithCustomFields(alias, i.CustomFields)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (i *Issuer) UnmarshalJSON(data []byte) error {
	var issuerID string

	if err := json.Unmarshal(data, &issuerID); err == nil {
		i.ID = issuerID
		return nil
	}

	type Alias Issuer
	alias := (*Alias)(i)
	i.CustomFields = make(CustomFields)

	err := jsonutil.UnmarshalWithCustomFields(data, alias, i.CustomFields)
	if err != nil {
		return err
	}

	if i.ID == "" {
		return errors.New("issuer ID is not defined")
	}

	return nil
}

func parseIssuer(issuerBytes json.RawMessage) (Issuer, error) {
	if len(issuerBytes) == 0 {
		return Issuer{}, nil
	}

	var issuer Issuer
	err := json.Unmarshal(issuerBytes, &issuer)
	if err != nil {
		return Issuer{}, err
	}

	return issuer, nil
}
