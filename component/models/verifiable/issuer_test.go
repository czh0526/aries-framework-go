package verifiable

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJSON_Marshal(t *testing.T) {
	issuer := &Issuer{
		ID: "123",
		CustomFields: CustomFields{
			"field1": "value1",
			"field2": "value2",
		},
	}

	issuerBytes, err := json.Marshal(issuer)
	assert.NoError(t, err)
	fmt.Printf("%s\n", issuerBytes)
}

func TestJSON_Unmarshal(t *testing.T) {
	issuerBytes := []byte(`{"id":"123","field1":"value1","field2":"value2"}`)

	issuer := &Issuer{}
	err := json.Unmarshal(issuerBytes, issuer)
	assert.NoError(t, err)
	assert.Equal(t, "123", issuer.ID)
	assert.Equal(t, "value1", issuer.CustomFields["field1"])
	assert.Equal(t, "value2", issuer.CustomFields["field2"])
}
