package issuer

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"sort"
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

		// 将 disclosures 按 key 排序, 便于检查值
		sort.Slice(disclosures, func(i, j int) bool { return disclosures[i].Key < disclosures[j].Key })

		assert.Equal(t, "address", disclosures[0].Key)
		assert.Equal(t, "country", disclosures[1].Key)
		assert.Equal(t, "DE", disclosures[1].Value)
		assert.Equal(t, "locality", disclosures[2].Key)
		assert.Equal(t, "Schulpforta", disclosures[2].Value)
		assert.Equal(t, "region", disclosures[3].Key)
		assert.Equal(t, "Sachsen-Anhalt", disclosures[3].Value)
		assert.Equal(t, "street_address", disclosures[4].Key)
		assert.Equal(t, "Schulstr. 12", disclosures[4].Value)

	})

	t.Run("recursive with array and include always", func(t *testing.T) {
		var parsedInput map[string]interface{}
		err := json.Unmarshal([]byte(sampleV5ComplexData), &parsedInput)
		assert.NoError(t, err)

		bb := NewSDJWTBuilderV5()
		bb.debugMode = true

		disclosures, finalMap, err := bb.CreateDisclosuresAndDigests(
			"", parsedInput,
			&newOpts{
				jsonMarshal: json.Marshal,
				HashAlg:     defaultHash,
				getSalt:     bb.GenerateSalt,
				alwaysInclude: map[string]bool{
					"address.extraArrInclude": true,
					"address.extra":           true,
				},
				nonSDClaimsMap: map[string]bool{
					"address.extraArrInclude[1]": true,
					"address.region":             true,
				},
				recursiveClaimMap: map[string]bool{
					"address":                 true,
					"address.extra.recursive": true,
				},
			})
		assert.NoError(t, err)

		printObject(t, "final credentials", finalMap)
		printObject(t, "disclosures", disclosures)
	})
}
