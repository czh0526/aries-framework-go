package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	josecipher "github.com/go-jose/go-jose/v3/cipher"
	hybridsubtle "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"math/big"
)

const defKeySize = 32

func (c *Crypto) deriveKEKAndWrap(cek, apu, apv, tag []byte, senderKH interface{}, recPubKey *spicrypto.PublicKey,
	epkPrv *spicrypto.PrivateKey, useXC20PKW bool) (*spicrypto.RecipientWrappedKey, error) {
	var (
		kek         []byte
		epk         *spicrypto.PublicKey
		wrappingAlg string
		err         error
	)

	if senderKH != nil {
		wrappingAlg, kek, epk, apu, err = c.derive1PUKEK(len(cek), apu, apv, tag, senderKH, recPubKey, epkPrv, useXC20PKW)
		if err != nil {
			return nil, fmt.Errorf("derivekEKAndWrap: error ECDH-1PU kek derivation: %w", err)
		}
	} else {
		wrappingAlg, kek, epk, apu, err = c.deriveESKEK(apu, apv, recPubKey, useXC20PKW)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: error ECDH-ES kek derivation: %w", err)
		}
	}

	return c.wrapRaw(kek, cek, apu, apv, wrappingAlg, recPubKey.KID, epk, useXC20PKW)
}

func (c *Crypto) wrapRaw(kek, cek, apu, apv []byte, alg, kid string, epk *spicrypto.PublicKey,
	useXC20PKW bool) (*spicrypto.RecipientWrappedKey, error) {
	var wk []byte

	if useXC20PKW {
		aead, err := c.okpKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to create new XC20P primitive: %w", err)
		}

		wk, err = c.okpKW.wrap(aead, cek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to wrap XC20P key: %w", err)
		}
	} else {
		block, err := c.ecKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to create new AES Cipher: %w", err)
		}

		wk, err = c.ecKW.wrap(block, cek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndWrap: failed to wrap AES cipher: %w", err)
		}
	}

	return &spicrypto.RecipientWrappedKey{
		KID:          kid,
		EncryptedCEK: wk,
		EPK:          *epk,
		APU:          apu,
		APV:          apv,
		Alg:          alg,
	}, nil
}

func (c *Crypto) deriveESKEK(apu, apv []byte, recPubKey *spicrypto.PublicKey,
	useXC20PKW bool) (string, []byte, *spicrypto.PublicKey, []byte, error) {
	var (
		kek         []byte
		epk         *spicrypto.PublicKey
		wrappingAlg string
		err         error
	)

	switch recPubKey.Type {
	case ecdhpb.KeyType_EC.String():
		wrappingAlg, kek, epk, apu, err = c.deriveESWithECKey(apu, apv, recPubKey, useXC20PKW)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("deriveESKEK: error %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		wrappingAlg, kek, epk, apu, err = c.deriveESWithOKPKey(apu, apv, recPubKey, useXC20PKW)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("deriveESKEK: error %w", err)
		}
	default:
		return "", nil, nil, nil, errors.New("deriveESKEK: invalid recipient key type for ECDH-ES")
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (c *Crypto) derive1PUKEK(cekSize int, apu, apv, tag []byte, senderKH interface{}, recPubKey *spicrypto.PublicKey,
	epkPrv *spicrypto.PrivateKey, useXC20PKW bool) (string, []byte, *spicrypto.PublicKey, []byte, error) {

	var (
		kek         []byte
		epk         *spicrypto.PublicKey
		wrappingAlg string
		err         error
	)

	two := 2

	if useXC20PKW {
		wrappingAlg = ECDH1PUXC20PKWAlg
	} else {
		switch cekSize {
		case subtle.AES128Size * two:
			wrappingAlg = ECDH1PUA128KWAlg
		case subtle.AES192Size * two:
			wrappingAlg = ECDH1PUA192KWAlg
		case subtle.AES256Size * two:
			wrappingAlg = ECDH1PUA256KWAlg
		default:
			return "", nil, nil, nil, fmt.Errorf("derive1PUKEK: invalid CBC-HMAC key size: %d", cekSize)
		}
	}

	switch recPubKey.Type {
	case ecdhpb.KeyType_EC.String():
		wrappingAlg, kek, epk, apu, err = c.derive1PUWithECKey(wrappingAlg, apu, apv, tag, senderKH, recPubKey, epkPrv)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("derive1PUKEK: EC key derivation error %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		wrappingAlg, kek, epk, apu, err = c.derive1PUWithOKPKey(wrappingAlg, apu, apv, tag, senderKH, recPubKey, epkPrv)
		if err != nil {
			return "", nil, nil, nil, fmt.Errorf("derive1PUKEK: OKP key derivation error %w", err)
		}
	default:
		return "", nil, nil, nil, errors.New("derive1PUKEK: invalid recipient key type for ECDH-1PU")
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (c *Crypto) deriveESWithECKey(apu, apv []byte, recPubKey *spicrypto.PublicKey,
	useXC20PKW bool) (string, []byte, *spicrypto.PublicKey, []byte, error) {
	wrappingAlg := ECDHESA256KWAlg
	if useXC20PKW {
		wrappingAlg = ECDHESXC20PKWAlg
	}

	recECPubKey, ephemeralPrivKey, err := c.convertRecKeyAndGenOrGetEPKEC(recPubKey, nil)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("deriveESWithECKey: failed to generate ephemeral key: %w", err)
	}

	ephemeralXBytes := ephemeralPrivKey.PublicKey.X.Bytes()

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralXBytes)))
		base64.RawURLEncoding.Encode(apu, ephemeralXBytes)
	}

	kek := josecipher.DeriveECDHES(wrappingAlg, apu, apv, ephemeralPrivKey, recECPubKey, defKeySize)
	epk := &spicrypto.PublicKey{
		X:     ephemeralXBytes,
		Y:     ephemeralPrivKey.PublicKey.Y.Bytes(),
		Curve: ephemeralPrivKey.PublicKey.Curve.Params().Name,
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (c *Crypto) derive1PUWithECKey(wrappingAlg string, apu, apv, tag []byte, senderKH interface{},
	recPubKey *spicrypto.PublicKey, epkPrv *spicrypto.PrivateKey) (string, []byte, *spicrypto.PublicKey, []byte, error) {
	// 获取 sender 的 ECDSA Key
	senderPrivKey, err := ksToPrivateECDSAKey(senderKH)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithECKey: failed to retrieve sender key: %w", err)
	}

	// 转换 receiver public key, 随机生成 ephemeral private Key
	pubKey, ephemeralPrivKey, err := c.convertRecKeyAndGenOrGetEPKEC(recPubKey, epkPrv)
	if err != nil {
		return "", nil, nil, nil, err
	}

	ephemeralXBytes := ephemeralPrivKey.PublicKey.X.Bytes()

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralXBytes)))
		base64.RawURLEncoding.Encode(apu, ephemeralXBytes)
	}

	keySize := aesCEKSize1PU(wrappingAlg)

	// 构建 KEK
	kek, err := c.ecKW.deriveSender1Pu(wrappingAlg, apu, apv, tag, ephemeralPrivKey, senderPrivKey, pubKey, keySize)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithECKey: failed to derive key: %w", err)
	}

	// 将 ephemeral public key 打包返回
	epk := &spicrypto.PublicKey{
		X:     ephemeralXBytes,
		Y:     ephemeralPrivKey.Y.Bytes(),
		Curve: ephemeralPrivKey.PublicKey.Curve.Params().Name,
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (c *Crypto) deriveESWithOKPKey(apu, apv []byte, recPubKey *spicrypto.PublicKey,
	useXC20PKW bool) (string, []byte, *spicrypto.PublicKey, []byte, error) {
	wrappingAlg := ECDHESA256KWAlg

	if useXC20PKW {
		wrappingAlg = ECDHESXC20PKWAlg
	}

	ephemeralPubKey, ephemeralPrivKey, err := c.generateOrGetEphemeralOKPKey(nil)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("deriveESWithOKPKey: failed to generate ephemeral key: %w", err)
	}

	ephemeralPrivChacha := new([chacha20poly1305.KeySize]byte)
	copy(ephemeralPrivChacha[:], ephemeralPrivKey)

	recPubKeyChacha := new([chacha20poly1305.KeySize]byte)
	copy(recPubKeyChacha[:], recPubKey.X)

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralPubKey)))
		base64.RawURLEncoding.Encode(apu, ephemeralPubKey)
	}

	z, err := cryptoutil.DeriveECDHX25519(ephemeralPrivChacha, recPubKeyChacha)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("deriveESWithOKPKey: failed to 25519 kek: %w", err)
	}

	kek := kdf(wrappingAlg, z, apu, apv, chacha20poly1305.KeySize)

	epk := &spicrypto.PublicKey{
		X:     ephemeralPubKey,
		Curve: "X25519",
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func (c *Crypto) derive1PUWithOKPKey(wrappingAlg string, apu, apv, tag []byte, senderKH interface{},
	recPubKey *spicrypto.PublicKey, epkPrv *spicrypto.PrivateKey) (string, []byte, *spicrypto.PublicKey, []byte, error) {
	senderPrivKey, err := ksToPrivateX25519Key(senderKH)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithOKPKey: failed to retrieve sender key: %w", err)
	}

	ephemeralPubKey, ephemeralPrivKey, err := c.generateOrGetEphemeralOKPKey(epkPrv)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithOKPKey: failed to generate ephemeral key: %w", err)
	}

	if len(apu) == 0 {
		apu = make([]byte, base64.RawURLEncoding.EncodedLen(len(ephemeralPubKey)))
		base64.RawURLEncoding.Encode(apu, ephemeralPubKey)
	}

	kek, err := c.okpKW.deriveSender1Pu(wrappingAlg, apu, apv, tag, ephemeralPrivKey, senderPrivKey, recPubKey.X,
		defKeySize)
	if err != nil {
		return "", nil, nil, nil, fmt.Errorf("derive1PUWithOKPKey: failed to derive key: %w", err)
	}

	epk := &spicrypto.PublicKey{
		X:     ephemeralPubKey,
		Curve: "X25519",
		Type:  recPubKey.Type,
	}

	return wrappingAlg, kek, epk, apu, nil
}

func aesCEKSize1PU(alg string) int {
	keySize := defKeySize
	two := 2

	switch alg {
	case ECDH1PUA128KWAlg:
		keySize = subtle.AES128Size * two
	case ECDH1PUA192KWAlg:
		keySize = subtle.AES192Size * two
	case ECDH1PUA256KWAlg:
		keySize = subtle.AES256Size * two
	}
	return keySize
}

func (c *Crypto) convertRecKeyAndGenOrGetEPKEC(recPubKey *spicrypto.PublicKey,
	prvEPK *spicrypto.PrivateKey) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	curve, err := c.ecKW.getCurve(recPubKey.Curve)
	if err != nil {
		return nil, nil, fmt.Errorf("convertRecKeyAndGenOrGetEPKEC: failed to get curve of recipient key: %w",
			err)
	}

	// 将原始的 receiver public key 对应的椭圆曲线上的点转换成 ECDSA 椭圆曲线上的点
	recECPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(recPubKey.X),
		Y:     new(big.Int).SetBytes(recPubKey.Y),
	}

	if prvEPK == nil {
		ephemeralPrivKey, err := c.ecKW.generateKey(recECPubKey.Curve)
		if err != nil {
			return nil, nil, fmt.Errorf("convertRecKeyAndGenOrGetEPKEC: failed to generate EPK: %w", err)
		}

		return recECPubKey, ephemeralPrivKey.(*ecdsa.PrivateKey), nil
	}

	return recECPubKey, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(prvEPK.PublicKey.X),
			Y:     new(big.Int).SetBytes(prvEPK.PublicKey.Y),
		},
		D: new(big.Int).SetBytes(prvEPK.D),
	}, nil
}

func (c *Crypto) generateOrGetEphemeralOKPKey(epkPrv *spicrypto.PrivateKey) ([]byte, []byte, error) {
	if epkPrv == nil {
		ephemeralPrivKey, err := c.okpKW.generateKey(nil)
		if err != nil {
			return nil, nil, err
		}

		ephemeralPrivKeyByte, ok := ephemeralPrivKey.([]byte)
		if !ok {
			return nil, nil, errors.New("invalid ephemeral key type, not OKP, want []byte for OKP")
		}

		ephemeralPubKey, err := curve25519.X25519(ephemeralPrivKeyByte, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}

		return ephemeralPubKey, ephemeralPrivKeyByte, nil
	}

	return epkPrv.PublicKey.X, epkPrv.D, nil
}

func (c *Crypto) deriveKEKAndUnwrap(alg string, encCEK, apu, apv, tag []byte, epk *spicrypto.PublicKey,
	senderKH interface{}, recKH interface{}) ([]byte, error) {
	var (
		kek []byte
		err error
	)

	recPrivKH, ok := recKH.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("deriveKEKAndUnwrap: %w", errBadKeyHandleFormat)
	}

	recipientPrivateKey, err := extractPrivKey(recPrivKH)
	if err != nil {
		return nil, fmt.Errorf("deriveKEKAndUnwrap: %w", err)
	}

	switch alg {
	case ECDH1PUA128KWAlg, ECDH1PUA192KWAlg, ECDH1PUA256KWAlg, ECDH1PUXC20PKWAlg:
		kek, err = c.derive1PUKEKForUnwrap(alg, apu, apv, tag, epk, senderKH, recipientPrivateKey)
	case ECDHESA256KWAlg, ECDHESXC20PKWAlg:
		kek, err = c.deriveESKEKForUnwrap(alg, apu, apv, epk, recipientPrivateKey)
	default:
		return nil, fmt.Errorf("deriveKEKAndUnwrap: unsupported JWE KW Alg: '%s'", alg)
	}

	return c.unwrapRaw(alg, kek, encCEK)
}

func (c *Crypto) unwrapRaw(alg string, kek, encCEK []byte) ([]byte, error) {
	var wk []byte

	switch alg {
	case ECDHESXC20PKWAlg, ECDH1PUXC20PKWAlg:
		aead, err := c.okpKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to create new XC20P primitive: %w", err)
		}

		wk, err = c.okpKW.unwrap(aead, encCEK)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to unwrap XC20P key: %w", err)
		}
	case ECDHESA256KWAlg, ECDH1PUA128KWAlg, ECDH1PUA192KWAlg, ECDH1PUA256KWAlg:
		block, err := c.ecKW.createPrimitive(kek)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to create new AES Cipher: %w", err)
		}

		wk, err = c.ecKW.unwrap(block, encCEK)
		if err != nil {
			return nil, fmt.Errorf("deriveKEKAndUnwrap: failed to unwrap AES Cipher: %w", err)
		}
	}

	return wk, nil
}

func (c *Crypto) derive1PUKEKForUnwrap(alg string, apu, apv, tag []byte, epk *spicrypto.PublicKey,
	senderKH interface{}, recipientPrivateKey interface{}) ([]byte, error) {
	var (
		kek []byte
		err error
	)

	if senderKH == nil {
		return nil, fmt.Errorf("derive1PUKEKForUnwrap: sender's public keyset handle option is required for '%s'",
			ECDH1PUA256KWAlg)
	}

	switch epk.Type {
	case ecdhpb.KeyType_EC.String():
		kek, err = c.derive1PUWithECKeyForUnwrap(alg, apu, apv, tag, epk, senderKH, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("derive1PUKEKForUnwrap: EC key derivation error: %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		kek, err = c.derive1PUWithOKPKeyForUnwrap(alg, apu, apv, tag, epk, senderKH, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("derive1PUKEKForUnwrap: OKP key derivation error: %w", err)
		}
	default:
		return nil, errors.New("derive1PPUKEKForUnwrap: invalid EPK key type for ECDH-1PU")
	}

	return kek, nil
}

func (c *Crypto) deriveESKEKForUnwrap(alg string, apu, apv []byte, epk *spicrypto.PublicKey,
	recipientPrivateKey interface{}) ([]byte, error) {
	var (
		kek []byte
		err error
	)

	switch epk.Type {
	case ecdhpb.KeyType_EC.String():
		kek, err = c.deriveESWithECKeyForUnwrap(alg, apu, apv, epk, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("deriveESKEKForUnwrap: error: %w", err)
		}
	case ecdhpb.KeyType_OKP.String():
		kek, err = c.deriveESWithOKPKeyForUnwrap(alg, apu, apv, epk, recipientPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("deriveESKEKForUnwrap: error: %w", err)
		}
	default:
		return nil, errors.New("deriveESKEKForUnwrap: invalid EPK key type for ECDH-ES")
	}

	return kek, nil
}

func (c *Crypto) derive1PUWithECKeyForUnwrap(alg string, apu, apv, tag []byte, epk *spicrypto.PublicKey,
	senderKH interface{}, recipientPrivateKey interface{}) ([]byte, error) {
	var (
		senderPubKey *ecdsa.PublicKey
		epkCurve     elliptic.Curve
		err          error
	)

	// 获取 sender 的 public key
	senderPubKey, err = ksToPublicECDSAKey(senderKH, c.ecKW)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithECKeyForUnwrap: failed to retrive sender public key: %w", err)
	}

	// 提取 ephemeral public key
	epkCurve, err = c.ecKW.getCurve(epk.Curve)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithECKeyForUnwrap: failed to GetCurve: %w", err)
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(epk.X),
		Y:     new(big.Int).SetBytes(epk.Y),
	}

	// 获取 recipient 的 private key
	recPrivECKey, ok := recipientPrivateKey.(*hybridsubtle.ECPrivateKey)
	if !ok {
		return nil, errors.New("derive1PUWithECKeyForUnwrap: invalid key is not an EC key")
	}

	recPrivKey := hybridECPrivToECDSAKey(recPrivECKey)

	keySize := aesCEKSize1PU(alg)

	// 派生 recipient 的共享密钥
	kek, err := c.ecKW.deriveRecipient1Pu(alg, apu, apv, tag, epkPubKey, senderPubKey, recPrivKey, keySize)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithECKeyForUnwrap: failed to derive kek: %w", err)
	}

	return kek, nil
}

func (c *Crypto) derive1PUWithOKPKeyForUnwrap(alg string, apu, apv, tag []byte, epk *spicrypto.PublicKey,
	senderKH interface{}, recipientPrivateKey interface{}) ([]byte, error) {
	senderPubKey, err := ksToPublicX25519Key(senderKH)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithOKPKeyForUnwrap: failed to retrive sender public key: %w", err)
	}

	recPrivOKPKey, ok := recipientPrivateKey.([]byte)
	if !ok {
		return nil, errors.New("derive1PUWithOKPKeyForUnwrap: recipient key is not an OKP key")
	}

	kek, err := c.okpKW.deriveRecipient1Pu(alg, apu, apv, tag, epk.X, senderPubKey, recPrivOKPKey, defKeySize)
	if err != nil {
		return nil, fmt.Errorf("derive1PUWithOKPKeyForUnwrap: failed to derive kek: %w", err)
	}

	return kek, nil
}

func (c *Crypto) deriveESWithECKeyForUnwrap(alg string, apu, apv []byte, epk *spicrypto.PublicKey,
	recipientPrivateKey interface{}) ([]byte, error) {
	var (
		epkCurve elliptic.Curve
		err      error
	)

	epkCurve, err = c.ecKW.getCurve(epk.Curve)
	if err != nil {
		return nil, fmt.Errorf("deriveESWithECKeyForUnwrap: failed to get GetCurve: %w", err)
	}

	epkPubKey := &ecdsa.PublicKey{
		Curve: epkCurve,
		X:     new(big.Int).SetBytes(epk.X),
		Y:     new(big.Int).SetBytes(epk.Y),
	}

	recPrivKevECKey, ok := recipientPrivateKey.(*hybridsubtle.ECPrivateKey)
	if !ok {
		return nil, errors.New("deriveESWithECKeyForUnwrap: recipient key is not an EC key")
	}

	recPrivKey := hybridECPrivToECDSAKey(recPrivKevECKey)

	if recPrivKey.Curve != epkPubKey.Curve {
		return nil, errors.New("deriveESWithECKeyForUnwrap: recipient and ephemeral keys are not on the same curve")
	}

	return josecipher.DeriveECDHES(alg, apu, apv, recPrivKey, epkPubKey, defKeySize), nil
}

func (c *Crypto) deriveESWithOKPKeyForUnwrap(alg string, apu, apv []byte, epk *spicrypto.PublicKey,
	recipientPrivateKey interface{}) ([]byte, error) {
	recPrivOKPKey, ok := recipientPrivateKey.([]byte)
	if !ok {
		return nil, errors.New("deriveESWithOKPKeyForUnwrap: recipient key is not an OKP key")
	}

	recPrivKeyChacha := new([chacha20poly1305.KeySize]byte)
	copy(recPrivKeyChacha[:], recPrivOKPKey)

	epkChacha := new([chacha20poly1305.KeySize]byte)
	copy(epkChacha[:], epk.X)

	z, err := cryptoutil.DeriveECDHX25519(recPrivKeyChacha, epkChacha)
	if err != nil {
		return nil, fmt.Errorf("deriveESWithOKPKeyForUnwrap: %w", err)
	}

	return kdf(alg, z, apu, apv, chacha20poly1305.KeySize), nil
}

func ksToPrivateECDSAKey(ks interface{}) (*ecdsa.PrivateKey, error) {
	senderKH, ok := ks.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("ksToPrivateECDSAKey: %w", errBadKeyHandleFormat)
	}

	senderHPrivKey, err := extractPrivKey(senderKH)
	if err != nil {
		return nil, fmt.Errorf("ksToPrivateECDSAKey: failed to extract sender key: %w", err)
	}

	prvKey, ok := senderHPrivKey.(*hybridsubtle.ECPrivateKey)
	if !ok {
		return nil, errors.New("ksToPrivateECDSAKey: not an EC key")
	}

	return hybridECPrivToECDSAKey(prvKey), nil
}

func ksToPublicECDSAKey(ks interface{}, kw keyWrapper) (*ecdsa.PublicKey, error) {
	switch kst := ks.(type) {
	case *keyset.Handle:
		sPubKey, err := keyio.ExtractPrimaryPublicKey(kst)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicECDSAKey: failed to extract primary public key from keyset handle: %w", err)
		}

		sCurve, err := kw.getCurve(sPubKey.Curve)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicECDSAKey: failed to GetCurve: %w", err)
		}

		return &ecdsa.PublicKey{
			Curve: sCurve,
			X:     new(big.Int).SetBytes(sPubKey.X),
			Y:     new(big.Int).SetBytes(sPubKey.Y),
		}, nil
	case *spicrypto.PublicKey:
		sCurve, err := kw.getCurve(kst.Curve)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicECDSAKey: failed to GetCurve: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: sCurve,
			X:     new(big.Int).SetBytes(kst.X),
			Y:     new(big.Int).SetBytes(kst.Y),
		}, nil
	case *ecdsa.PublicKey:
		return kst, nil
	default:
		return nil, fmt.Errorf("ksToPublicECDSAKey: unsupported keyset type: %T", kst)
	}
}

func ksToPrivateX25519Key(ks interface{}) ([]byte, error) {
	senderKH, ok := ks.(*keyset.Handle)
	if !ok {
		return nil, fmt.Errorf("ksToPrivateX25519Key: %w", errBadKeyHandleFormat)
	}

	senderPrivKey, err := extractPrivKey(senderKH)
	if err != nil {
		return nil, fmt.Errorf("ksToPrivateX25519Key: failed to extract sender key: %w", err)
	}

	prvKey, ok := senderPrivKey.([]byte)
	if !ok {
		return nil, errors.New("ksToPrivateX25519Key: not an OKP key")
	}

	return prvKey, nil
}

func ksToPublicX25519Key(ks interface{}) ([]byte, error) {
	switch kst := ks.(type) {
	case *keyset.Handle:
		sPubKey, err := keyio.ExtractPrimaryPublicKey(kst)
		if err != nil {
			return nil, fmt.Errorf("ksToPublicX25519Key: failed to extract primary public key from keyset handle: %w", err)
		}
		return sPubKey.X, nil
	case *spicrypto.PublicKey:
		return kst.X, nil
	default:
		return nil, fmt.Errorf("ksToPublicX25519Key: unsupported keyset type: %T", kst)
	}
}
