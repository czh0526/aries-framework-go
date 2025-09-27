package crypto

import spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"

type SignFunc func([]byte, interface{}) ([]byte, error)

type Crypto struct {
	EncryptValue      []byte
	EncryptNonceValue []byte
	EncryptErr        error
	DecryptValue      []byte
	DecryptErr        error
	SignValue         []byte
	SignKey           []byte
	SignFn            SignFunc
	SignErr           error
	VerifyErr         error
	ComputeMACValue   []byte
	ComputeMACErr     error
	VerifyMACErr      error
	WrapValue         *spicrypto.RecipientWrappedKey
	WrapError         error
	UnwrapValue       []byte
	UnwrapErr         error
}

func (c *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, error) {
	return c.EncryptValue, c.EncryptErr
}

func (c *Crypto) Decrypt(cipher, aad []byte, kh interface{}) ([]byte, error) {
	return c.DecryptValue, c.DecryptErr
}

func (c *Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	if c.SignFn != nil {
		return c.SignFn(msg, c.SignKey)
	}
	return c.SignValue, c.SignErr
}

func (c *Crypto) Verify(signature, msg []byte, kh interface{}) error {
	return c.VerifyErr
}

func (c *Crypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (c *Crypto) VerifyMAC(mac, data []byte, kh interface{}) error {
	return c.VerifyMACErr
}

func (c *Crypto) WrapKey(cek, apu, apv []byte, recPubKey *spicrypto.PublicKey, opts ...spicrypto.WrapKeyOpts) (*spicrypto.RecipientWrappedKey, error) {
	return c.WrapValue, c.WrapError
}

func (c *Crypto) UnwrapKey(recWK *spicrypto.RecipientWrappedKey, kh interface{}, opts ...spicrypto.WrapKeyOpts) ([]byte, error) {
	return c.UnwrapValue, c.UnwrapErr
}

var _ spicrypto.Crypto = (*Crypto)(nil)
