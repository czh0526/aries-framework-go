package suite

import "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmssigner"

type signer interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

var _ signer = (*kmssigner.KMSSigner)(nil)

type SignatureSuite struct {
	Signer signer
}

type Opt func(opts *SignatureSuite)

func WithSigner(s signer) Opt {
	return func(opts *SignatureSuite) {
		opts.Signer = s
	}
}
