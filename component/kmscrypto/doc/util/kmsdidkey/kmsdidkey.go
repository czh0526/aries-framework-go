package kmsdidkey

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

func EncryptionPubKeyFromDIDKey(didKey string) (*spicrypto.PublicKey, error) {
	pubKey, code, err := extractRawKey(didKey)
	if err != nil {
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %v", err)
	}

	var (
		crv   string
		kmtKT spikms.KeyType
		kt    string
		x     []byte
		y     []byte
	)

	switch code {
	case fingerprint.ED25519PubKeyMultiCodec:
	case fingerprint.X25519PubKeyMultiCodec:
		var (
			mPubXKey []byte
			xKID     string
		)

		kmtKT = spikms.X25519ECDHKWType
		pubXKey := &spicrypto.PublicKey{
			X:     pubKey,
			Curve: "X25519",
			Type:  "OKP",
		}

		mPubXKey, err = json.Marshal(pubXKey)
		if err != nil {
			return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: %v", err)
		}

		xKID, err = jwkkid.C

	case fingerprint.P256PubKeyMultiCodec:
		kmtKT = spikms.ECDSAP256TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P256(), pubKey)

	case fingerprint.P384PubKeyMultiCodec:
		kmtKT = spikms.ECDSAP384TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P384(), pubKey)

	case fingerprint.P521PubKeyMultiCodec:
		kmtKT = spikms.ECDSAP521TypeIEEEP1363
		kt = "EC"
		crv, x, y, pubKey = unmarshalECKey(elliptic.P521(), pubKey)

	default:
		return nil, fmt.Errorf("encryptionPubKeyFromDIDKey: unsupported key multicodec code [0x%x]", code)
	}
}

func extractRawKey(didKey string) ([]byte, uint64, error) {
	idMethodSpecificID, err := fingerprint.MethodIDFromDIDKey(didKey)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: fingerprint.MethodIDFromDIDKey failure: %v", err)
	}

	pubKey, code, err := fingerprint.PubKeyFromFingerprint(idMethodSpecificID)
	if err != nil {
		return nil, 0, fmt.Errorf("extractRawKey: fingerprint.PubKeyFromFingerprint failure: %v", err)
	}

	return pubKey, code, nil
}
