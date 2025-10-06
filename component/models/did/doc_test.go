package did

import (
	_ "embed"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	//go:embed testdata/valid_doc_with_base.jsonld
	validDocWithBase string
)

func TestValidWithDocBase(t *testing.T) {
	docs := []string{validDocWithBase}
	for _, d := range docs {
		doc, err := ParseDocument([]byte(d))
		require.NoError(t, err)
		require.NotNil(t, doc)

		context, ok := doc.Context.([]string)
		require.True(t, ok)
		require.Contains(t, context[0], "https://www.w3.org/ns/did/v")
	}
}
