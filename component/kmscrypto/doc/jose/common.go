package jose

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
)

const (
	HeaderAlgorithm = "alg"

	HeaderEncryption = "enc"

	HeaderKeyID = "kid"

	HeaderSenderKeyID = "skid"

	HeaderType = "typ"

	HeaderContentType = "cty"

	HeaderCritical = "crit"

	HeaderEPK = "epk"
)

const (
	HeaderB64Payload = "b64"
	A256GCMALG       = "A256GCM"
	XC20PALG         = "XC20P"
	A128CBCHS256ALG  = "A128CBC-HS256"
	A192CBCHS384ALG  = "A192CBC-HS384"
	A256CBCHS384ALG  = "A256CBC-HS384"
	A256CBCHS512ALG  = "A256CBC-HS512"
)

var aeadAlg = map[EncAlg]ecdh.AEADAlg{
	A256GCM:      ecdh.AES256GCM,
	XC20P:        ecdh.XC20P,
	A128CBCHS256: ecdh.AES128CBCHMACSHA256,
	A192CBCHS384: ecdh.AES192CBCHMACSHA384,
	A256CBCHS384: ecdh.AES256CBCHMACSHA384,
	A256CBCHS512: ecdh.AES256CBCHMACSHA512,
}

type Headers map[string]interface{}

func (h Headers) Type() (string, bool) {
	return h.stringValue(HeaderType)
}

func (h Headers) ContentType() (string, bool) {
	return h.stringValue(HeaderContentType)
}

func (h Headers) KeyID() (string, bool) {
	return h.stringValue(HeaderKeyID)
}

func (h Headers) Encryption() (string, bool) {
	return h.stringValue(HeaderEncryption)
}

func (h Headers) stringValue(key string) (string, bool) {
	raw, ok := h[key]
	if !ok {
		return "", false
	}

	str, ok := raw.(string)

	return str, ok
}
