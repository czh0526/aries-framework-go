package vdr

type DIDMethodOpts struct {
	Values map[string]interface{}
}

type DIDMethodOption func(opts *DIDMethodOpts)

func WithOption(name string, value interface{}) DIDMethodOption {
	return func(opts *DIDMethodOpts) {
		opts.Values[name] = value
	}
}
