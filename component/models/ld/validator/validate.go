package validator

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/models/ld/processor"
	"github.com/czh0526/aries-framework-go/component/models/util/json"
	jsonld "github.com/piprate/json-gold/ld"
	"reflect"
	"strings"
)

type validateOpts struct {
	strict               bool
	jsonldDocumentLoader jsonld.DocumentLoader
	externalContext      []string
	contextURIPositions  []string
}

type ValidateOpts func(opts *validateOpts)

func WithDocumentLoader(jsonldDocumentLoader jsonld.DocumentLoader) ValidateOpts {
	return func(opts *validateOpts) {
		opts.jsonldDocumentLoader = jsonldDocumentLoader
	}
}

func WithExternalContext(externalContext []string) ValidateOpts {
	return func(opts *validateOpts) {
		opts.externalContext = externalContext
	}
}

func WithStrictValidation(strict bool) ValidateOpts {
	return func(opts *validateOpts) {
		opts.strict = strict
	}
}

func WithStrictContextURIPosition(uri string) ValidateOpts {
	return func(opts *validateOpts) {
		opts.contextURIPositions = append(opts.contextURIPositions, uri)
	}
}

func getValidateOpts(options []ValidateOpts) *validateOpts {
	result := &validateOpts{
		strict: true,
	}

	for _, opt := range options {
		opt(result)
	}

	return result
}

func ValidateJSONLD(doc string, options ...ValidateOpts) error {
	docMap, err := json.ToMap(doc)
	if err != nil {
		return fmt.Errorf("convert JSON-LD doc to map: %w", err)
	}

	return ValidateJSONLDMap(docMap, options...)
}

func ValidateJSONLDMap(docMap map[string]interface{}, options ...ValidateOpts) error {
	opts := getValidateOpts(options)

	jsonldProc := processor.Default()

	docCompactedMap, err := jsonldProc.Compact(docMap, nil,
		processor.WithDocumentLoader(opts.jsonldDocumentLoader),
		processor.WithExternalContext(opts.externalContext...))
	if err != nil {
		return fmt.Errorf("compact JSON-LD document: %w", err)
	}

	if opts.strict && !mapsHaveSomeStructure(docMap, docCompactedMap) {
		return errors.New("JSON-LD doc has different structure after compaction")
	}

	err = validateContextURIPosition(opts.contextURIPositions, docMap)
	if err != nil {
		return fmt.Errorf("validate context URI positions: %w", err)
	}

	return nil
}

func mapsHaveSomeStructure(originalMap, compactedMap map[string]interface{}) bool {
	original := compactMap(originalMap)
	compacted := compactMap(compactedMap)

	if reflect.DeepEqual(original, compacted) {
		return true
	}

	if len(original) != len(compacted) {
		return false
	}

	for k, v1 := range original {
		v1Map, isMap := v1.(map[string]interface{})
		if !isMap {
			continue
		}

		v2, present := compacted[k]
		if !present {
			continue
		}

		v2Map, isMap := v2.(map[string]interface{})
		if !isMap {
			return false
		}

		if !mapsHaveSomeStructure(v1Map, v2Map) {
			return false
		}
	}

	return true
}

func compactMap(m map[string]interface{}) map[string]interface{} {
	mCopy := make(map[string]interface{})

	for k, v := range m {
		if k == "@context" {
			continue
		}

		vNorm := compactValue(v)

		switch kv := vNorm.(type) {
		case []interface{}:
			mCopy[k] = compactSlice(kv)
		case map[string]interface{}:
			mCopy[k] = compactMap(kv)
		default:
			mCopy[k] = vNorm
		}
	}

	return mCopy
}

func compactSlice(s []interface{}) []interface{} {
	sCopy := make([]interface{}, len(s))

	for i := range s {
		sItem := compactValue(s[i])

		switch v := sItem.(type) {
		case map[string]interface{}:
			sCopy[i] = compactMap(v)
		default:
			sCopy[i] = v
		}
	}

	return sCopy
}

func compactValue(v interface{}) interface{} {
	switch cv := v.(type) {
	case []interface{}:
		if len(cv) == 1 {
			return compactValue(cv[0])
		}

		return cv

	case map[string]interface{}:
		if len(cv) == 1 {
			if _, ok := cv["id"]; ok {
				return cv["id"]
			}
		}
		return cv

	default:
		return cv
	}
}

func validateContextURIPosition(contextURIPositions []string, docMap map[string]interface{}) error {
	if len(contextURIPositions) == 0 {
		return nil
	}

	var docContexts []interface{}

	switch t := docMap["@context"].(type) {
	case string:
		docContexts = append(docContexts, t)
	case []interface{}:
		docContexts = append(docContexts, t...)
	}

	if len(docContexts) < len(contextURIPositions) {
		return errors.New("doc context URIs amount mismatch")
	}

	for position, uri := range contextURIPositions {
		docURI, ok := docContexts[position].(string)
		if !ok {
			return fmt.Errorf("unsupported URI type %s", reflect.TypeOf(docContexts[position]).String())
		}

		if !strings.EqualFold(docURI, uri) {
			return fmt.Errorf("invalid context URI on position %d, %s expected", position, uri)
		}
	}

	return nil
}
