package kms

type keyOpts struct {
	attrs []string
}

type KeyOpts func(opts *keyOpts)

func WithAttrs(attrs []string) KeyOpts {
	return func(opts *keyOpts) {
		opts.attrs = attrs
	}
}
