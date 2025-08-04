package localkms

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"io"
)

type CryptoBox struct {
	km *LocalKMS
}

func (c *CryptoBox) Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c *CryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c *CryptoBox) Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c *CryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

var _ kms.CryptoBox = (*CryptoBox)(nil)

func NewCryptoBox(km spikms.KeyManager) (*CryptoBox, error) {
	lkms, ok := km.(*LocalKMS)
	if !ok {
		return nil, fmt.Errorf("cannot use parameter argument as KMS")
	}

	return &CryptoBox{km: lkms}, nil
}
