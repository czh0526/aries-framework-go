package jose

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	resolver "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type Decrypter interface {
	Decrypt(jwe *JSONWebEncryption) ([]byte, error)
}

type JWEDecrypt struct {
	kidResolvers []resolver.KIDResolver
	crypto       spicrypto.Crypto
	kms          spikms.KeyManager
}

func (jd *JWEDecrypt) Decrypt(jwe *JSONWebEncryption) ([]byte, error) {
	encAlg, err := jd.validateAndExtractProtectedHeaders(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: %w", err)
	}

	var wkOpts []spicrypto.WrapKeyOpts
}

func (jd *JWEDecrypt) decryptJWE(jwe *JSONWebEncryption, cek []byte) ([]byte, error) {
	encAlg, ok := jwe.ProtectedHeaders.Encryption()
	if !ok {
		return nil, fmt.Errorf("jwedecrypt: JWE 'enc'' protected header is missing")
	}

	decPrimitive, err := getECDHDecPrimitive(cek, EncAlg(encAlg), true)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to get decryption primitive: %w", err)
	}

	encryptedData, err := buildEncryptedData(jwe)
	if err != nil {
		return nil, fmt.Errorf("jwedecrypt: failed to build encryptedData for Decrypt(): %w", err)
	}
}

func NewJWEDecrypt(kidResolvers []resolver.KIDResolver, c spicrypto.Crypto, k spikms.KeyManager) *JWEDecrypt {
	return &JWEDecrypt{
		kidResolvers: kidResolvers,
		crypto:       c,
		kms:          k,
	}
}

func getECDHDecPrimitive(cek []byte, encAlg EncAlg, nistpKW bool) (api.CompositeDecrypt, error) {
	ceAlg := aeadAlg[encAlg]

	if ceAlg <= 0 {
		return nil, fmt.Errorf("invalid content encAlg: '%s'", encAlg)
	}

	kt := ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, nistpKW, ceAlg)

	kh, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	return ecdh.NewECDHDecrypt(kh)
}
