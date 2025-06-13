package kms

type privateKeyOpts struct {
	ksID string
}

func (pk *privateKeyOpts) KsID() string {
	return pk.ksID
}

func NewOpt() *privateKeyOpts {
	return &privateKeyOpts{}
}

type PrivateKeyOpts func(opt *privateKeyOpts)

func WithKeyID(keyID string) PrivateKeyOpts {
	return func(opt *privateKeyOpts) {
		opt.ksID = keyID
	}
}
