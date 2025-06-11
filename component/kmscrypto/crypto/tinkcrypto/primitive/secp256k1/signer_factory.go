package secp256k1

import (
	"fmt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

func NewSigner(kh *keyset.Handle) (tink.Signer, error) {
	return newWrappedSigner(kh)
}

type wrappedSigner struct {
	kh *keyset.Handle
}

func (w *wrappedSigner) Sign(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

var _ tink.Signer = (*wrappedSigner)(nil)

func newWrappedSigner(kh *keyset.Handle) (*wrappedSigner, error) {
	return &wrappedSigner{
		kh: kh,
	}, nil
}
