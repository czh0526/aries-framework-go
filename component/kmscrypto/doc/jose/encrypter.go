package jose

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead/subtle"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/api"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/subtle/random"
)

type EncAlg string

const (
	A256GCM      = EncAlg(A256GCMALG)
	XC20P        = EncAlg(XC20PALG)
	A128CBCHS256 = EncAlg(A128CBCHS256ALG)
	A192CBCHS384 = EncAlg(A192CBCHS384ALG)
	A256CBCHS384 = EncAlg(A256CBCHS384ALG)
	A256CBCHS512 = EncAlg(A256CBCHS512ALG)
)

type EncEncrypter interface {
	EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error)

	Encrypt(plaintext []byte) (*JSONWebEncryption, error)
}

type JWEEncrypt struct {
	recipientsKeys []*spicrypto.PublicKey
	skid           string
	senderKH       *keyset.Handle
	encAlg         EncAlg
	encTyp         string
	cty            string
	crypto         spicrypto.Crypto
}

func (je *JWEEncrypt) Encrypt(plaintext []byte) (*JSONWebEncryption, error) {
	return je.EncryptWithAuthData(plaintext, nil)
}

func (je *JWEEncrypt) EncryptWithAuthData(plaintext, aad []byte) (*JSONWebEncryption, error) {
	protectedHeaders := map[string]interface{}{
		HeaderEncryption: je.encAlg,
		HeaderType:       je.encTyp,
	}
	je.addExtraProtectedHeaders(protectedHeaders)

	cek := je.newCEK()

	encPrimitive, err := je.getECDHEncPrimitive(cek)
}

func NewJWEEncrypt(encAlg EncAlg, envelopMediaType, cty, senderKID string, senderKH *keyset.Handle,
	recipientsPubKeys []*spicrypto.PublicKey, crypto spicrypto.Crypto) (*JWEEncrypt, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, errors.New("empty recipientsPubKeys list")
	}

	switch encAlg {
	case A256GCM, XC20P, A128CBCHS256, A192CBCHS384, A256CBCHS384, A256CBCHS512:
	default:
		return nil, fmt.Errorf("encryption algorithm '%s' not supported", encAlg)
	}

	if crypto == nil {
		return nil, errors.New("crypto service is required to create a JWEEncrypt instance")
	}

	if senderKH != nil {
		if senderKID == "" {
			return nil, errors.New("senderKID is required with senderKH")
		}
	}

	return &JWEEncrypt{
		recipientsKeys: recipientsPubKeys,
		skid:           senderKID,
		senderKH:       senderKH,
		encAlg:         encAlg,
		encTyp:         envelopMediaType,
		cty:            cty,
		crypto:         crypto,
	}, nil
}

func (je *JWEEncrypt) addExtraProtectedHeaders(protectedHeaders map[string]interface{}) {
	if je.cty != "" {
		protectedHeaders[HeaderContentType] = je.cty
	}

	if je.skid != "" {
		protectedHeaders[HeaderSenderKeyID] = je.skid
	}
}

func (je *JWEEncrypt) newCEK() []byte {
	twoKeys := 2
	defKeySize := 32

	switch je.encAlg {
	case A256GCM, XC20P:
		return random.GetRandomBytes(uint32(defKeySize))
	case A128CBCHS256:
		return random.GetRandomBytes(uint32(subtle.AES128Size * twoKeys))
	case A192CBCHS384:
		return random.GetRandomBytes(uint32(subtle.AES192Size * twoKeys))
	case A256CBCHS384:
		return random.GetRandomBytes(uint32(subtle.AES256Size + subtle.AES192Size))
	case A256CBCHS512:
		return random.GetRandomBytes(uint32(subtle.AES256Size * twoKeys))
	default:
		return random.GetRandomBytes(uint32(defKeySize))
	}
}

func (je *JWEEncrypt) useNISTPKW() bool {
	if je.senderKH == nil {
		return true
	}

	for _, ki := range je.senderKH.KeysetInfo().KeyInfo {
		switch ki.TypeUrl {
		case "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey",
			"type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey":
			return true
		case "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey",
			"type.hedgerledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey":
			return false
		}
	}
	return true
}

func (je *JWEEncrypt) getECDHEncPrimitive(cek []byte) (api.CompositeEncrypt, error) {
	nistpKW := je.useNISTPKW()

	encAlg, ok := aeadAlg[je.encAlg]
	if !ok {
		return nil, fmt.Errorf("getECDHEncPrimitive: encAlg not supported: '%v'", je.encAlg)
	}

	kt := ecdh.KeyTemplateForECDHPrimitiveWithCEK(cek, nistpKW, encAlg)

	kh, err := keyset.NewHandle(kt)
	if err != nil {
		return nil, err
	}

	pubKH, err := kh.Public()
	if err != nil {
		return nil, err
	}

	return ecdh.NewECDHEncrypt(pubKH)
}
