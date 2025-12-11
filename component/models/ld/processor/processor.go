package processor

import "github.com/piprate/json-gold/ld"

type processorOpts struct {
	removeInvalidRDF bool
	frameBlankNodes  bool
	validateRDF      bool
	documentLoader   ld.DocumentLoader
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

func WithDocumentLoader(loader ld.DocumentLoader) Opts {
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
