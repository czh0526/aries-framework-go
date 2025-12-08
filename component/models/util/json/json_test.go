package json

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

type testJSON struct {
	S []string `json:"stringSlice"`
	I int      `json:"intValue"`
}

func Test_marshalJSON(t *testing.T) {
	t.Run("Successful JSON marshaling", func(T *testing.T) {
		v := testJSON{
			S: []string{"a", "b", "c"},
			I: 8,
		}

		cf := map[string]interface{}{
			"boolValue": false,
			"intValue":  8,
		}

		actual, err := MarshalWithCustomFields(&v, cf)
		require.NoError(t, err)

		expectedMap := map[string]interface{}{
			"stringSlice": []string{"a", "b", "c"},
			"intValue":    8,
			"boolValue":   false,
		}
		expected, err := json.Marshal(expectedMap)
		require.NoError(t, err)

		require.EqualValues(t, expected, actual)
	})
}

func Test_unmarshalJSON(t *testing.T) {
	originalMap := map[string]interface{}{
		"stringSlice": []string{"a", "b", "c"},
		"intValue":    7,
		"boolValue":   false,
	}

	data, err := json.Marshal(originalMap)
	require.NoError(t, err)

	t.Run("Successful JSON unmarshalling", func(t *testing.T) {
		v := new(testJSON)
		cf := make(map[string]interface{})
		err = UnmarshalWithCustomFields(data, v, cf)
		require.NoError(t, err)

		expectedV := testJSON{
			S: []string{"a", "b", "c"},
			I: 7,
		}
		expectedEf := map[string]interface{}{
			"boolValue": false,
		}
		require.Equal(t, expectedV, *v)
		require.Equal(t, expectedEf, cf)
	})
}
