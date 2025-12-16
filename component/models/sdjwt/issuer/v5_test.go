package issuer

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	sampleV5ComplexData = `{
	  "address": {
		"street_address": "Schulstr. 12",
		"locality": "Schulpforta",
		"region": "Sachsen-Anhalt",
		"country": "DE",
		"extraArrInclude" : ["UA", "PL"],
		"extraArr" : ["Extra1", "Extra2"],
		"extra" : {
			"recursive" : {
				"key1" : "value1"
			}
		}
	  }
	}`

	sampleV5AddressMapTestData = `{
	  "address": {
		"street_address": "Schulstr. 12",
		"locality": "Schulpforta",
		"region": "Sachsen-Anhalt",
		"country": {
		  "code" : "DE"
		}
	  }
	}`

	sampleV5TestData = `{
	  "some_map": {
		"a" : "b"
	  },
	  "nationalities": [
		"US",
		"DE"
	  ]
	}`

	simpleV5TestData = `{
	  "some_arr" : ["UA"]
	}`

	arrayTwoElementsV5TestData = `{
	  "some_arr" : ["UA", "PL"]
	}`

	addressV5TestData = `{
	  "address": {
		"postal_code": "12345",
		"locality": "Irgendwo",
		"street_address": "Sonnenstrasse 23",
		"country_code": "DE"
	  }
	}`
)

func TestDisclosureV5Map(t *testing.T) {
	t.Run("recursive", func(t *testing.T) {
		input := `{
		  "address": {
			"street_address": "Schulstr. 12",
			"locality": "Schulpforta",
			"region": "Sachsen-Anhalt",
			"country": "DE"
		  }
		}`

		var parsedInput map[string]interface{}
		err := json.Unmarshal([]byte(input), &parsedInput)
		assert.NoError(t, err)
		bb := NewSDJWTBuilderV5()

		disclosures, cred, err := bb.CreateDisclosuresAndDigests("", parsedInput, &newOpts{
			jsonMarshal: json.Marshal,
			HashAlg:     defaultHash,
			getSalt:     bb.GenerateSalt,
			recursiveClaimMap: map[string]bool{
				"address": true,
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, 5, len(disclosures))
		assert.Equal(t, 1, len(cred))

	})
}
