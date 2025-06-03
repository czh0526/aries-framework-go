package kms

type privateKeyOpts struct {
	ksID string
}

type PrivateKeyOpts func(opt *privateKeyOpts)

func WithKeyID(keyID string) PrivateKeyOpts {
	return func(opt *privateKeyOpts) {
		opt.ksID = keyID
	}
}
