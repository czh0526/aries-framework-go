package localkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	secp256k1subtle "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1/subtle"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"google.golang.org/protobuf/proto"
	"io"
	"math/big"
)

const (
	ecdsaVerifierTypeURL         = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	ed25519VerifierTypeURL       = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"
	nistPECDHKWPublicKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
	x25519ECDHKWPublicKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
	bbsVerifierKeyTypeURL        = "type.hyperledger.org/hyperledger.aries.crypto.tink.BBSPublicKey"
	clCredDefKeyTypeURL          = "type.hyperledger.org/hyperledger.aries.crypto.tink.CLCredDefKey"
	secp256k1VerifierTypeURL     = "type.googleapis.com/google.crypto.tink.secp256k1PublicKey"
	derPrefix                    = "der-"
	p1363Prefix                  = "p1363-"
)

var ecdsaKMSKeyTypes = map[string]spikms.KeyType{
	derPrefix + "NIST_P256":   spikms.ECDSAP256TypeDER,
	derPrefix + "NIST_P384":   spikms.ECDSAP384DER,
	derPrefix + "NIST_P521":   spikms.ECDSAP521TypeDER,
	derPrefix + "SECP256K1":   spikms.ECDSASecp256k1DER,
	p1363Prefix + "NIST_P256": spikms.ECDSAP256TypeIEEEP1363,
	p1363Prefix + "NIST_P384": spikms.ECDSAP384TypeIEEEP1363,
	p1363Prefix + "NIST_P521": spikms.ECDSAP521TypeIEEEP1363,
	p1363Prefix + "SECP256K1": spikms.ECDSAP256TypeIEEEP1363,
}

type PubKeyWriter struct {
	KeyType spikms.KeyType
	w       io.Writer
}

func (p PubKeyWriter) Write(keyset *tinkpb.Keyset) error {
	keyType, err := write(p.w, keyset)
	if err != nil {
		return err
	}

	p.KeyType = keyType
	return nil
}

func (p PubKeyWriter) WriteEncrypted(keyset *tinkpb.EncryptedKeyset) error {
	return fmt.Errorf("write encrypted function not supported")
}

func NewWriter(w io.Writer) *PubKeyWriter {
	return &PubKeyWriter{
		w: w,
	}
}

// write 将 msg 中包含的 primary key 写入到 writer 中
func write(w io.Writer, msg *tinkpb.Keyset) (spikms.KeyType, error) {
	ks := msg.Key
	primaryKID := msg.PrimaryKeyId
	created := false

	var (
		kt  spikms.KeyType
		err error
	)
	for _, key := range ks {
		if key.KeyId == primaryKID && key.Status == tinkpb.KeyStatusType_ENABLED {
			switch key.KeyData.TypeUrl {
			case ecdsaVerifierTypeURL, ed25519VerifierTypeURL, secp256k1VerifierTypeURL,
				bbsVerifierKeyTypeURL, clCredDefKeyTypeURL:
				created, kt, err = writePubKey(w, key)
				if err != nil {
					return "", err
				}
			default:
				return "", fmt.Errorf("key type not supported for writing raw key bytes: %v", key.KeyData.TypeUrl)
			}

			break
		}
	}

	if !created {
		return "", fmt.Errorf("key not written")
	}

	return kt, nil
}

// writePubKey 将 Protobuf 结构的公钥进行 tink 编码，并写入 writer
// 区分两种编码类型：DER 和 IEEE_P1363
func writePubKey(w io.Writer, key *tinkpb.Keyset_Key) (bool, spikms.KeyType, error) {
	var (
		marshaledRawPubKey []byte
		kt                 spikms.KeyType
	)

	switch key.KeyData.TypeUrl {
	case ecdsaVerifierTypeURL:
		pubKeyProto := new(ecdsapb.EcdsaPublicKey)
		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}
		marshaledRawPubKey, kt, err = getMarshalledECDSAKeyValueFromProto(pubKeyProto)
		if err != nil {
			return false, "", err
		}

	case ed25519VerifierTypeURL:
		pubKeyProto := new(ed25519pb.Ed25519PublicKey)
		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}
		marshaledRawPubKey = make([]byte, len(pubKeyProto.KeyValue))
		copy(marshaledRawPubKey, pubKeyProto.KeyValue)

		kt = spikms.ED25519Type

	case secp256k1VerifierTypeURL:
		pubKeyProto := new(secp256k1pb.Secp256K1PublicKey)
		err := proto.Unmarshal(key.KeyData.Value, pubKeyProto)
		if err != nil {
			return false, "", err
		}

		marshaledRawPubKey, kt, err = getMarshalledSecp256K1KeyValueFromProto(pubKeyProto)
		if err != nil {
			return false, "", err
		}

	default:
		return false, "", fmt.Errorf("can't export key with keyURL: %s", key.KeyData.TypeUrl)
	}

	n, err := w.Write(marshaledRawPubKey)
	if err != nil {
		return false, "", err
	}

	return n > 0, kt, nil
}

// getMarshalledECDSAKeyValueFromProto 处理 ECDSA Protobuf 结构
func getMarshalledECDSAKeyValueFromProto(pubKeyProto *ecdsapb.EcdsaPublicKey) ([]byte, spikms.KeyType, error) {
	var (
		marshaledRawPubKey []byte
		kt                 spikms.KeyType
		err                error
	)

	curveName := commonpb.EllipticCurveType_name[int32(pubKeyProto.Params.Curve)]
	curve := subtle.GetCurve(curveName)
	if curve == nil {
		return nil, "", fmt.Errorf("undefined curve")
	}

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(pubKeyProto.X),
		Y:     new(big.Int).SetBytes(pubKeyProto.Y),
	}

	switch pubKeyProto.Params.Encoding {
	case ecdsapb.EcdsaSignatureEncoding_DER:
		marshaledRawPubKey, err = x509.MarshalPKIXPublicKey(&pubKey)
		if err != nil {
			return nil, "", err
		}

		kt = ecdsaKMSKeyTypes[derPrefix+curveName]

	case ecdsapb.EcdsaSignatureEncoding_IEEE_P1363:
		marshaledRawPubKey = elliptic.Marshal(curve, pubKey.X, pubKey.Y)
		kt = ecdsaKMSKeyTypes[p1363Prefix+curveName]

	default:
		return nil, "", fmt.Errorf("can't export key with bad key encoding:  %v", pubKeyProto.Params.Encoding)
	}

	return marshaledRawPubKey, kt, nil
}

// getMarshalledSecp256K1KeyValueFromProto 处理 Secp256K1 Protobuf 结构
func getMarshalledSecp256K1KeyValueFromProto(pkPB *secp256k1pb.Secp256K1PublicKey) ([]byte, spikms.KeyType, error) {
	var (
		marshaledRawPubKey []byte
		err                error
		kt                 spikms.KeyType
	)

	curveName := secp256k1pb.BitcoinCurveType_name[int32(pkPB.Params.Curve)]
	curve := secp256k1subtle.GetCurve(curveName)
	if curve == nil {
		return nil, "", fmt.Errorf("undefined curve")
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(pkPB.X),
		Y:     new(big.Int).SetBytes(pkPB.Y),
	}

	switch pkPB.Params.Encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER:
		marshaledRawPubKey, err = x509.MarshalPKIXPublicKey(&pubKey)
		if err != nil {
			return nil, "", err
		}

		kt = ecdsaKMSKeyTypes[derPrefix+curveName]

	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363:
		marshaledRawPubKey = elliptic.Marshal(curve, pubKey.X, pubKey.Y)
		kt = ecdsaKMSKeyTypes[p1363Prefix+curveName]

	default:
		return nil, "", fmt.Errorf("can't export key with bad key encoding:  %v", pkPB.Params.Encoding)
	}

	return marshaledRawPubKey, kt, nil
}
