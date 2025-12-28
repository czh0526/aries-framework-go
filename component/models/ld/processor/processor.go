package processor

import jsonld "github.com/piprate/json-gold/ld"

const (
	format           = "application/n-quads"
	defaultAlgorithm = "URDNA2015"
)

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
