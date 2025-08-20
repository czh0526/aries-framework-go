package tinkcrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	josecipher "github.com/go-jose/go-jose/v3/cipher"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"golang.org/x/crypto/chacha20poly1305"
)

type keyWrapper interface {
	getCurve(curve string) (elliptic.Curve, error)
	generateKey(curve elliptic.Curve) (interface{}, error)
	createPrimitive(key []byte) (interface{}, error)
	wrap(blockPrimitive interface{}, cek []byte) ([]byte, error)
	unwrap(blockPrimitive interface{}, encryptedKey []byte) ([]byte, error)
	deriveSender1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPriv, senderPrivKey, recPubKey interface{},
		keySize int) ([]byte, error)
	deriveRecipient1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPub, senderPubKey, recPrivKey interface{},
		keySize int) ([]byte, error)
}

type ecKWSupport struct{}

func (w *ecKWSupport) getCurve(curve string) (elliptic.Curve, error) {
	return hybrid.GetCurve(curve)
}

func (w *ecKWSupport) generateKey(curve elliptic.Curve) (interface{}, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func (w *ecKWSupport) createPrimitive(kek []byte) (interface{}, error) {
	return aes.NewCipher(kek)
}

func (w *ecKWSupport) wrap(blockPrimitive interface{}, cek []byte) ([]byte, error) {
	blockCipher, ok := blockPrimitive.(cipher.Block)
	if !ok {
		return nil, errors.New("wrap support: EC wrap with invalid cipher block type")
	}

	return josecipher.KeyWrap(blockCipher, cek)
}

func (w *ecKWSupport) unwrap(blockPrimitive interface{}, encryptedKey []byte) ([]byte, error) {
	blockCipher, ok := blockPrimitive.(cipher.Block)
	if !ok {
		return nil, errors.New("unwrap support: EC wrap with invalid cipher block type")
	}

	return josecipher.KeyUnwrap(blockCipher, encryptedKey)
}

func (w *ecKWSupport) deriveSender1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPriv, senderPrivKey, recPubKey interface{}, keySize int) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (w *ecKWSupport) deriveRecipient1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPub, senderPubKey, recPrivKey interface{}, keySize int) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

var _ keyWrapper = (*ecKWSupport)(nil)

type okpKWSupport struct{}

func (w *okpKWSupport) getCurve(curve string) (elliptic.Curve, error) {
	return nil, errors.New("getCurve: not implemented for OKP KW support")
}

func (w *okpKWSupport) generateKey(_ elliptic.Curve) (interface{}, error) {
	newKey := make([]byte, cryptoutil.Curve25519KeySize)

	_, err := rand.Read(newKey)
	if err != nil {
		return nil, fmt.Errorf("generateKey: failed to create X25519 random key: %w", err)
	}

	return newKey, nil
}

func (w *okpKWSupport) createPrimitive(kek []byte) (interface{}, error) {
	p, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return nil, fmt.Errorf("createPrimitive: failed to create OKP primitive: %w", err)
	}

	return p, nil
}

func (w *okpKWSupport) wrap(aead interface{}, cek []byte) ([]byte, error) {
	aeadPrimitive, ok := aead.(cipher.AEAD)
	if !ok {
		return nil, errors.New("wrap support: OKP wrap with invalid primitive type")
	}

	nonceSize := aeadPrimitive.NonceSize()
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("wrap support: failed to generate random nonce: %w", err)
	}

	cipherText := aeadPrimitive.Seal(nil, nonce, cek, nil)

	return append(nonce, cipherText...), nil
}

func (w *okpKWSupport) unwrap(aead interface{}, encryptedKey []byte) ([]byte, error) {
	aeadPrimitive, ok := aead.(cipher.AEAD)
	if !ok {
		return nil, errors.New("unwrap support: OKP wrap with invalid primitive type")
	}

	if len(encryptedKey) < aeadPrimitive.NonceSize() {
		return nil, errors.New("unwrap support: OKP unwrap invalid key")
	}

	nonce := encryptedKey[:aeadPrimitive.NonceSize()]

	cek, err := aeadPrimitive.Open(nil, nonce, encryptedKey[aeadPrimitive.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap support: OKP failed to unwrap key: %w", err)
	}

	return cek, nil
}

func (w *okpKWSupport) deriveSender1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPriv, senderPrivKey, recPubKey interface{}, keySize int) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (w *okpKWSupport) deriveRecipient1Pu(kwAlg string, apu, apv, tag []byte, ephemeralPub, senderPubKey, recPrivKey interface{}, keySize int) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

var _ keyWrapper = (*okpKWSupport)(nil)

func kdf(kwAlg string, z, apu, apv []byte, keySize int) []byte {
	return kdfWithTag(kwAlg, z, apu, apv, nil, keySize, false)
}

func kdfWithTag(kwAlg string, z, apu, apv, tag []byte, keySize int, useTag bool) []byte {
	algID := cryptoutil.LengthPrefix([]byte(kwAlg))
	ptyUInfo := cryptoutil.LengthPrefix(apu)
	ptyVInfo := cryptoutil.LengthPrefix(apv)

	supPubLen := 4
	supPubInfo := make([]byte, supPubLen)

	byteLen := 8
	kdfKeySize := keySize

	switch kwAlg {
	case ECDH1PUA128KWAlg:
		kdfKeySize = subtle.AES128Size
	case ECDH1PUA192KWAlg:
		kdfKeySize = subtle.AES192Size
	case ECDH1PUA256KWAlg:
		kdfKeySize = subtle.AES256Size
	}

	binary.BigEndian.PutUint32(supPubInfo, uint32(kdfKeySize)*uint32(byteLen))

	if useTag {
		tagInfo := cryptoutil.LengthPrefix(tag)
		supPubInfo = append(supPubInfo, tagInfo...)
	}

	reader := josecipher.NewConcatKDF(crypto.SHA256, z, algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})

	kek := make([]byte, kdfKeySize)
	_, _ = reader.Read(kek)

	return kek
}
