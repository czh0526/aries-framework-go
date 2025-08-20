package crypto

type wrapKeyOpts struct {
	senderKey  interface{}
	useXC20PKW bool
	tag        []byte
	epk        *PrivateKey
}

func (pk *wrapKeyOpts) Tag() []byte {
	return pk.tag
}

func (pk *wrapKeyOpts) EPK() *PrivateKey {
	return pk.epk
}

func (pk *wrapKeyOpts) UseXC20PKW() bool {
	return pk.useXC20PKW
}

func (pk *wrapKeyOpts) SenderKey() interface{} {
	return pk.senderKey
}

func NewOpt() *wrapKeyOpts {
	return &wrapKeyOpts{}
}

type WrapKeyOpts func(opts *wrapKeyOpts)
