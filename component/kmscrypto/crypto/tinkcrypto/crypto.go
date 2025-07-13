package tinkcrypto

import (
	"errors"
	"fmt"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/signature"
)

var errBadKeyHandleFormat = errors.New("bad key handle format")

type Crypto struct {
	//ecKW  keyWrapper
	//okpKW keyWrapper
}

func (c *Crypto) Encrypt(msg, aad []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new aead: %w", err)
	}

	ct, err := a.Encrypt(msg, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt msg: %w", err)
	}

	return ct, nil
}

func (c *Crypto) Decrypt(cipher, aad []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	a, err := aead.New(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new aead failed: %w", err)
	}

	pt, err := a.Decrypt(cipher, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}

	return pt, nil
}

func (c *Crypto) Sign(msg []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	signer, err := signature.NewSigner(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("create new signer: %w", err)
	}

	sig, err := signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("sign msg: %w", err)
	}

	return sig, nil
}

func (c *Crypto) Verify(sig, msg []byte, kh interface{}) error {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return errBadKeyHandleFormat
	}

	verifier, err := signature.NewVerifier(keyHandle)
	if err != nil {
		return fmt.Errorf("create new verifier: %w", err)
	}

	err = verifier.Verify(sig, msg)
	if err != nil {
		err = fmt.Errorf("verify msg: %w", err)
	}

	return err
}

func (c *Crypto) ComputeMAC(data []byte, kh interface{}) ([]byte, error) {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return nil, errBadKeyHandleFormat
	}

	macPrimitive, err := mac.New(keyHandle)
	if err != nil {
		return nil, err
	}

	return macPrimitive.ComputeMAC(data)
}

func (c *Crypto) VerifyMAC(macBytes, data []byte, kh interface{}) error {
	keyHandle, ok := kh.(*keyset.Handle)
	if !ok {
		return errBadKeyHandleFormat
	}

	macPrimitive, err := mac.New(keyHandle)
	if err != nil {
		return err
	}

	return macPrimitive.VerifyMAC(macBytes, data)
}

var _ spicrypto.Crypto = (*Crypto)(nil)

func New() (*Crypto, error) {
	return &Crypto{
		//ecKW:  &ecKWSupport{},
		//okpKW: &okpKWSupport{},
	}, nil
}
