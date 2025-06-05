package ecdh

import (
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/google/tink/go/aead"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

type AEADAlg int

const (
	AES256GCM = iota + 1
	XC20P
	AES128CBCHMACSHA256
	AES192CBCHMACSHA384
	AES256CBCHMACSHA384
	AES256CBCHMACSHA521
)

func NISTP256ECDHKWKeyTemplate() *tinkpb.KeyTemplate {
	return createKeyTemplate()
}

func createKeyTemplate(nistpKW bool, encAlg AEADAlg, C commonpb.EllipticCurveType, cek []byte) *tinkpb.KeyTemplate {
	typeURL, keyType, encTemplate := getTypeTemplate(nistpKW, encAlg, cek)
}

func getTypeParams(nistpKW bool, encAlg AEADAlg, cek []byte) (string, ecdhpb.KeyType, *tinkpb.KeyTemplate) {
	var (
		keyTemplate *tinkpb.KeyTemplate
		twoKeys     = 2
	)

	switch encAlg {
	case AES256GCM:
		keyTemplate = aead.AES256GCMKeyTemplate()
	case AES128CBCHMACSHA256, AES192CBCHMACSHA384, AES256CBCHMACSHA384, AES256CBCHMACSHA521:
		switch len(cek) {
		case subtle.AES128Size
		}
	case XC20P:
		keyTemplate = aead.XChaCha20Poly1305KeyTemplate()
	}

	if nistpKW {
		return nistpECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_EC, keyTemplate
	}

	return x25519ECDHKWPrivateKeyTypeURL, ecdhpb.KeyType_OKP, keyTemplate
}
