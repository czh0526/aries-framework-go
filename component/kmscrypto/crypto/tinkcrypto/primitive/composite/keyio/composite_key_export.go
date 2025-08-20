package keyio

import (
	"bytes"
	"encoding/json"
	"fmt"
	ecdhpb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	hybrid "github.com/tink-crypto/tink-go/v2/hybrid/subtle"
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
