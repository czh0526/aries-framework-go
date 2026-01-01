package processor

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	jsonld "github.com/piprate/json-gold/ld"
	"strings"
)

const (
	format             = "application/n-quads"
	defaultAlgorithm   = "URDNA2015"
	handleNormalizeErr = "error while parsing N-Quads; invalid quad. line:"
)

var logger = log.New("aries-framework/json-ld-processor")

var ErrInvalidRDFFound = errors.New("invalid JSON-LD context")

type processorOpts struct {
	removeInvalidRDF bool
	frameBlankNodes  bool
	validateRDF      bool
	documentLoader   jsonld.DocumentLoader
	externalContexts []string
}

type Opts func(opts *processorOpts)

func WithRemoveAllInvalidRDF() Opts {
	return func(opts *processorOpts) {
		opts.removeInvalidRDF = true
	}
}

func WithFrameBlankNodes() Opts {
	return func(opts *processorOpts) {
		opts.frameBlankNodes = true
	}
}

func WithValidateRDF() Opts {
	return func(opts *processorOpts) {
		opts.validateRDF = true
	}
}

func WithDocumentLoader(loader jsonld.DocumentLoader) Opts {
	return func(opts *processorOpts) {
		opts.documentLoader = loader
	}
}

func WithExternalContext(context ...string) Opts {
	return func(opts *processorOpts) {
		opts.externalContexts = context
	}
}

func AppendExternalContexts(context interface{}, extraContexts ...string) []interface{} {
	var contexts []interface{}

	switch c := context.(type) {
	case string:
		contexts = append(contexts, c)
	case []interface{}:
		contexts = append(contexts, c...)
	}

	for i := range extraContexts {
		contexts = append(contexts, extraContexts[i])
	}

	return contexts
}

func prepareOpts(opts []Opts) *processorOpts {
	procOpts := &processorOpts{}

	for _, opt := range opts {
		opt(procOpts)
	}

	return procOpts
}

type Processor struct {
	algorithm string
}

func NewProcessor(algorithm string) *Processor {
	if algorithm == "" {
		return Default()
	}

	return &Processor{algorithm: algorithm}
}

func Default() *Processor {
	return &Processor{
		algorithm: defaultAlgorithm,
	}
}

func (p *Processor) Compact(input, context map[string]interface{},
	opts ...Opts) (map[string]interface{}, error) {
	procOptions := prepareOpts(opts)

	ldOptions := jsonld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = jsonld.JsonLd_1_1
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	if context == nil {
		inputContext := input["@context"]

		if len(procOptions.externalContexts) > 0 {
			inputContext = AppendExternalContexts(inputContext, procOptions.externalContexts...)
			input["@context"] = inputContext
		}

		context = map[string]interface{}{
			"@context": inputContext,
		}
	}

	return jsonld.NewJsonLdProcessor().Compact(input, context, ldOptions)
}

func (p *Processor) GetCanonicalDocument(doc map[string]interface{}, opts ...Opts) ([]byte, error) {
	procOptions := prepareOpts(opts)

	ldOptions := jsonld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = jsonld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	if len(procOptions.externalContexts) > 0 {
		doc["@context"] = AppendExternalContexts(doc["@context"], procOptions.externalContexts...)
	}

	proc := jsonld.NewJsonLdProcessor()

	view, err := proc.Normalize(doc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	result, ok := view.(string)
	if !ok {
		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
	}

	result, err = p.removeMatchingInvalidRDFs(result, procOptions)
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

func (p *Processor) removeMatchingInvalidRDFs(view string, opts *processorOpts) (string, error) {
	if !opts.removeInvalidRDF && !opts.validateRDF {
		return view, nil
	}

	views := strings.Split(view, "\n")

	var filteredViews []string
	var foundInvalid bool

	for _, v := range views {
		_, err := jsonld.ParseNQuads(v)
		if err != nil {
			if !strings.Contains(err.Error(), handleNormalizeErr) {
				return "", err
			}

			foundInvalid = true
			continue
		}

		filteredViews = append(filteredViews, v)
	}

	if !foundInvalid {
		return view, nil
	} else if opts.validateRDF {
		return "", ErrInvalidRDFFound
	}

	filteredView := strings.Join(filteredViews, "\n")
	logger.Debugf("Found invalid RDF dataset, Canonicalizing JON-LD again after removing invalid data")

	return p.normalizeFilteredDataset(filteredView)
}

func (p *Processor) normalizeFilteredDataset(view string) (string, error) {
	ldOptions := jsonld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = jsonld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format

	proc := jsonld.NewJsonLdProcessor()

	filteredJSONLd, err := proc.FromRDF(view, ldOptions)
	if err != nil {
		return "", err
	}

	result, err := proc.Normalize(filteredJSONLd, ldOptions)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}
