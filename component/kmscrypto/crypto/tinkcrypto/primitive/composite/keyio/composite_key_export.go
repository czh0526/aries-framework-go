package keyio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	tinkaead "github.com/tink-crypto/tink-go/v2/aead"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"
	"io"
	"strings"
)

const (
	nistPECDHKWPublicKeyTypeURL   = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
	x25519ECDHKWPublicKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
	nistPECDHKWPrivateKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
	x25519ECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"
)

var ecdhKeyTypes = map[string]spikms.KeyType{
	"NIST_P256": spikms.NISTP521ECDHKWType,
	"NIST_P384": spikms.NISTP384ECDHKWType,
	"NIST_P521": spikms.NISTP521ECDHKWType,
}

type PubKeyWriter struct {
	KeyType spikms.KeyType
	w       io.Writer
}

func (p *PubKeyWriter) WriteEncrypted(_ *tinkpb.EncryptedKeyset) error {
	return fmt.Errorf("write encrypted function not supported")
}

func NewWriter(w io.Writer) *PubKeyWriter {
	return &PubKeyWriter{
		w: w,
	}
}

func (p *PubKeyWriter) Write(ks *tinkpb.Keyset) error {
	return p.write(ks)
}

func (p *PubKeyWriter) write(msg *tinkpb.Keyset) error {
	ks := msg.Key
	primaryKID := msg.PrimaryKeyId
	created := false
	var err error

	for _, key := range ks {
		if key.KeyId == primaryKID && key.Status == tinkpb.KeyStatusType_ENABLED {
			created, err = p.writePubKey(key)
			if err != nil {
				return err
			}
			break
		}
	}

	if !created {
		return fmt.Errorf("key not written")
	}

	return nil
}

func (p *PubKeyWriter) writePubKey(key *tinkpb.Keyset_Key) (bool, error) {
	pubKey, kt, err := protoToCompositeKey(key.KeyData)
	if err != nil {
		return false, err
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return false, err
	}

	n, err := p.w.Write(mPubKey)
	if err != nil {
		return false, err
	}

	p.KeyType = kt
	return n > 0, nil
}

func protoToCompositeKey(keyData *tinkpb.KeyData) (*spicrypto.PublicKey, spikms.KeyType, error) {
	var (
		cKey compositeKeyGetter
		err  error
	)

	switch keyData.TypeUrl {
	case nistPECDHKWPublicKeyTypeURL, x25519ECDHKWPublicKeyTypeURL:
		cKey, err = newECDHKey(keyData.Value)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("can't export key with keyURL: %s", keyData.TypeUrl)
	}

	return buildKey(cKey)
}

func buildKey(c compositeKeyGetter) (*spicrypto.PublicKey, spikms.KeyType, error) {
	curveName := c.curveName()
	keyTypeName := c.keyType()

	return buildCompositeKey(c.kid(), keyTypeName, curveName, c.x(), c.y())
}

func buildCompositeKey(kid, keyType, curve string, x, y []byte) (*spicrypto.PublicKey, spikms.KeyType, error) {
	var kt spikms.KeyType

	switch keyType {
	case ecdhpb.KeyType_EC.String():
		_, err := hybrid.GetCurve(curve)
		if err != nil {
			return nil, "", fmt.Errorf("undefined EC curve: %w", err)
		}
		kt = ecdhKeyTypes[curve]

	case ecdhpb.KeyType_OKP.String():
		if curve != commonpb.EllipticCurveType_CURVE25519.String() {
			return nil, "", fmt.Errorf("invalid OKP curve: %s", curve)
		}

		curve = "X25519"
		kt = spikms.X25519ECDHKWType

	default:
		return nil, "", fmt.Errorf("invalid keyType: %s", keyType)
	}

	return &spicrypto.PublicKey{
		KID:   kid,
		Type:  keyType,
		Curve: curve,
		X:     x,
		Y:     y,
	}, kt, nil
}

type compositeKeyGetter interface {
	kid() string
	curveName() string
	keyType() string
	x() []byte
	y() []byte
}

type ecdhKey struct {
	protoKey *ecdhpb.EcdhAeadPublicKey
}

func (e *ecdhKey) kid() string {
	return e.protoKey.KID
}

func (e *ecdhKey) curveName() string {
	return e.protoKey.Params.KwParams.CurveType.String()
}

func (e *ecdhKey) keyType() string {
	return e.protoKey.Params.KwParams.KeyType.String()
}

func (e *ecdhKey) x() []byte {
	return e.protoKey.X
}

func (e *ecdhKey) y() []byte {
	return e.protoKey.Y
}

func newECDHKey(mKey []byte) (compositeKeyGetter, error) {
	pubKeyProto := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(mKey, pubKeyProto)
	if err != nil {
		return nil, err
	}

	return &ecdhKey{
		protoKey: pubKeyProto,
	}, nil
}

func ExtractPrimaryPublicKey(kh *keyset.Handle) (*spicrypto.PublicKey, error) {
	keyBytes, err := writePubKeyFromKeyHandle(kh)
	if err != nil {
		return nil, fmt.Errorf("extractPrimaryPublicKey: failed to get public key content: %w", err)
	}

	ecPubKey := new(spicrypto.PublicKey)

	err = json.Unmarshal(keyBytes, ecPubKey)
	if err != nil {
		return nil, fmt.Errorf("extractPrimaryPublicKey: unmarshal public key failed: %w", err)
	}

	return ecPubKey, nil
}

func PublicKeyToKeysetHandle(pubKey *spicrypto.PublicKey, aeadAlg ecdh.AEADAlg) (*keyset.Handle, error) {
	cp, err := getCurveProto(pubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to convert curve string to proto: %w", err)
	}

	kt, err := getKeyType(pubKey.Type)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to convert key type to proto: %w", err)
	}

	encT, keyURL, err := keyTemplateAndURL(cp, aeadAlg, true)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: %w", err)
	}

	protoKey := &ecdhpb.EcdhAeadPublicKey{
		Version: 0,
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: cp,
				KeyType:   kt,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encT,
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
		KID: pubKey.KID,
		X:   pubKey.X,
		Y:   pubKey.Y,
	}

	marshalledKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to marshal proto: %w", err)
	}

	ks := newKeySet(keyURL, marshalledKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	memReader := &keyset.MemReaderWriter{Keyset: ks}
	parsedHandle, err := insecurecleartextkeyset.Read(memReader)

	return parsedHandle, err
}

func PrivateKeyToKeysetHandle(privKey *spicrypto.PrivateKey, aeadAlg ecdh.AEADAlg) (*keyset.Handle, error) {
	cp, err := getCurveProto(privKey.PublicKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to convert curve string to proto: %w", err)
	}

	kt, err := getKeyType(privKey.PublicKey.Type)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to convert key type to proto: %w", err)
	}

	encT, keyURL, err := keyTemplateAndURL(cp, aeadAlg, false)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: %w", err)
	}

	protoKey := &ecdhpb.EcdhAeadPrivateKey{
		Version: 0,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params: &ecdhpb.EcdhAeadParams{
				KwParams: &ecdhpb.EcdhKwParams{
					CurveType: cp,
					KeyType:   kt,
				},
				EncParams: &ecdhpb.EcdhAeadEncParams{
					AeadEnc: encT,
				},
				EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
			},
			KID: privKey.PublicKey.KID,
			X:   privKey.PublicKey.X,
			Y:   privKey.PublicKey.Y,
		},
		KeyValue: privKey.D,
	}

	marshalledKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to marshal proto: %w", err)
	}

	ks := newKeySet(keyURL, marshalledKey, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

	memReader := &keyset.MemReaderWriter{Keyset: ks}

	parsedHandle, err := insecurecleartextkeyset.Read(memReader)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to create key handle: %w", err)
	}

	return parsedHandle, nil
}

var keyTemplateToPublicKeyURL = map[commonpb.EllipticCurveType]string{
	commonpb.EllipticCurveType_NIST_P256:  nistPECDHKWPublicKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P384:  nistPECDHKWPublicKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P521:  nistPECDHKWPublicKeyTypeURL,
	commonpb.EllipticCurveType_CURVE25519: x25519ECDHKWPublicKeyTypeURL,
}

var keyTemplateToPrivateKeyURL = map[commonpb.EllipticCurveType]string{
	commonpb.EllipticCurveType_NIST_P256:  nistPECDHKWPrivateKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P384:  nistPECDHKWPrivateKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P521:  nistPECDHKWPrivateKeyTypeURL,
	commonpb.EllipticCurveType_CURVE25519: nistPECDHKWPrivateKeyTypeURL,
}

func keyTemplateAndURL(cp commonpb.EllipticCurveType, aeadAlg ecdh.AEADAlg,
	isPublic bool) (*tinkpb.KeyTemplate, string, error) {
	var (
		encT   *tinkpb.KeyTemplate
		keyURL string
	)

	if isPublic {
		keyURL = keyTemplateToPublicKeyURL[cp]
	} else {
		keyURL = keyTemplateToPrivateKeyURL[cp]
	}

	if keyURL == "" {
		return nil, "", fmt.Errorf("invalid key curve: `%s`", cp)
	}

	switch aeadAlg {
	case ecdh.AES256GCM:
		encT = tinkaead.AES256GCMKeyTemplate()
	case ecdh.XC20P:
		encT = tinkaead.XChaCha20Poly1305KeyTemplate()
	case ecdh.AES128CBCHMACSHA256:
		encT = aead.AES128CBCHMACSHA256KeyTemplate()
	case ecdh.AES192CBCHMACSHA384:
		encT = aead.AES192CBCHMACSHA384KeyTemplate()
	case ecdh.AES256CBCHMACSHA384:
		encT = aead.AES256CBCHMACSHA384KeyTemplate()
	case ecdh.AES256CBCHMACSHA512:
		encT = aead.AES256CBCHMACSHA512KeyTemplate()
	default:
		return nil, "", fmt.Errorf("invalid encryption algorithm: `%s`", ecdh.EncryptionAlgLabel[aeadAlg])
	}

	return encT, keyURL, nil
}

func getKeyType(k string) (ecdhpb.KeyType, error) {
	switch k {
	case ecdhpb.KeyType_EC.String():
		return ecdhpb.KeyType_EC, nil
	case ecdhpb.KeyType_OKP.String():
		return ecdhpb.KeyType_OKP, nil
	default:
		return ecdhpb.KeyType_UNKNOWN_KEY_TYPE, errors.New("unknown key type")
	}
}

func getCurveProto(c string) (commonpb.EllipticCurveType, error) {
	switch c {
	case "secp256r1", "NIST_P256", "P-256", "EllipticCutveType_NIST_P256":
		return commonpb.EllipticCurveType_NIST_P256, nil
	case "secp384r1", "NIST_P384", "P-384", "EllipticCutveType_NIST_P384":
		return commonpb.EllipticCurveType_NIST_P384, nil
	case "secp521r1", "NIST_P521", "P-521", "EllipticCutveType_NIST_P521":
		return commonpb.EllipticCurveType_NIST_P521, nil
	case commonpb.EllipticCurveType_CURVE25519.String(), "X25519":
		return commonpb.EllipticCurveType_CURVE25519, nil
	default:
		return commonpb.EllipticCurveType_UNKNOWN_CURVE, errors.New("unsupported curve")
	}
}

func writePubKeyFromKeyHandle(kh *keyset.Handle) ([]byte, error) {
	pubKH, err := kh.Public()
	if err != nil {
		if strings.HasSuffix(err.Error(), "keyset contains a non-private key") {
			pubKH = kh
		} else {
			return nil, err
		}
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func newKeySet(tURL string, marshalledKey []byte, keyMaterialType tinkpb.KeyData_KeyMaterialType) *tinkpb.Keyset {
	keyData := &tinkpb.KeyData{
		TypeUrl:         tURL,
		Value:           marshalledKey,
		KeyMaterialType: keyMaterialType,
	}

	return &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData:          keyData,
				Status:           tinkpb.KeyStatusType_ENABLED,
				KeyId:            1,
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		PrimaryKeyId: 1,
	}
}
