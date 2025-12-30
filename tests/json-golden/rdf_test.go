package main

import (
	"fmt"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNormalize(t *testing.T) {
	data := map[string]interface{}{
		"@context": map[string]interface{}{
			"name":  "http://schema.org/name",
			"@base": "http://example.com/",
		},
		"@id":  "http://example.com/exampleID",
		"name": "exampleName",
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"

	normalized, err := proc.Normalize(data, options)
	assert.NoError(t, err)

	fmt.Printf("Normalized JSON-LD: %s\n", normalized)
}

func TestNormalize2(t *testing.T) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.Algorithm = ld.AlgorithmURDNA2015

	doc := map[string]interface{}{
		"@context": map[string]interface{}{
			"ex": "http://example.org/vocab#",
		},
		"@id":   "http://example.org/test#example",
		"@type": "ex:Foo",
		"ex:embed": map[string]interface{}{
			"@type": "ex:Bar",
		},
	}

	normalizedTriples, err := proc.Normalize(doc, options)
	if err != nil {
		panic(err)
	}

	print(normalizedTriples.(string))

}
