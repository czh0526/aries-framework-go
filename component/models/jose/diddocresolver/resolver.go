package diddocresolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"strings"
)

const (
	jsonWebKey2020            = "JsonWebKey2020"
	x25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019"
)

type vdrResolver interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*didmodel.DocResolution, error)
}

type DIDDocResolver struct {
	VDRRegistry vdrResolver
}

func (d *DIDDocResolver) Resolve(kid string) (*spicrypto.PublicKey, error) {
	var (
		pubKey *spicrypto.PublicKey
		err    error
	)

	if d.VDRRegistry == nil {
		return nil, errors.New("didDocResolver: missing vdr registry")
	}

	i := strings.Index(kid, "#")
	if i < 0 {
		return nil, fmt.Errorf("didDocResolver: kid is not KeyAgreement.ID: '%w'", kid)
	}

	didDoc, err := d.VDRRegistry.Resolve(kid[:i])
	if err != nil {
		return nil, fmt.Errorf("didDocResolver: for recipient DID doc resolution: err = %w", err)
	}

	for _, ka := range didDoc.DIDDocument.KeyAgreement {
		keyAgreementID := ka.VerificationMethod.ID

		if strings.HasPrefix(keyAgreementID, "#") {
			keyAgreementID = didDoc.DIDDocument.ID + keyAgreementID
		}

		if strings.EqualFold(kid, keyAgreementID) {
			pubKey, err = extractKey(&ka)
			if err != nil {
				return nil, err
			}
		}
	}
	return pubKey, nil
}

func extractKey(ka *didmodel.Verification) (*spicrypto.PublicKey, error) {
	var (
		pubKey *spicrypto.PublicKey
		err    error
	)

	switch ka.VerificationMethod.Type {
	case x25519KeyAgreementKey2019:
		pubKey, err = buildX25519Key(ka)
		if err != nil {
			return nil, fmt.Errorf("didDocResolver: %w", err)
		}
	case jsonWebKey2020:
		pubKey, err = buildJWKKey(ka)
		if err != nil {
			return nil, fmt.Errorf("didDocResolver: %w", err)
		}
	default:
		return nil, fmt.Errorf("didDocResolver: can't build key from KeyAgreement with type: `%v`",
			ka.VerificationMethod.Type)
	}

	return pubKey, nil
}

func buildX25519Key(ka *didmodel.Verification) (*spicrypto.PublicKey, error) {
	pubKey := &spicrypto.PublicKey{
		X:     ka.VerificationMethod.Value,
		Curve: "X25519",
		Type:  "OKP",
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return nil, fmt.Errorf("buildX25519: marshal key error: %w", err)
	}

	x25519KMSKID, err := jwkkid.CreateKID(mPubKey, spikms.X25519ECDHKWType)
	if err != nil {
		return nil, fmt.Errorf("buildX25519: createKID error: %w", err)
	}

	pubKey.KID = x25519KMSKID
	return pubKey, nil
}

func buildJWKKey(ka *didmodel.Verification) (*spicrypto.PublicKey, error) {
	var (
		x  []byte
		y  []byte
		kt spikms.KeyType
	)

	jwkKey := ka.VerificationMethod.JSONWebKey()
	switch k := jwkKey.Key.(type) {
	case *ecdsa.PublicKey:
		x = k.X.Bytes()
		y = k.Y.Bytes()
	case []byte:
		x = make([]byte, len(k))
		copy(x, k)
	default:
		return nil, fmt.Errorf("buildJWKKey: unsupported JWK format: (%T)", k)
	}

	pubKey := &spicrypto.PublicKey{
		X:     x,
		Y:     y,
		Curve: jwkKey.Crv,
		Type:  jwkKey.Kty,
	}

	switch jwkKey.Crv {
	case elliptic.P256().Params().Name:
		kt = spikms.NISTP256ECDHKWType
	case elliptic.P384().Params().Name:
		kt = spikms.NISTP384ECDHKWType
	case elliptic.P521().Params().Name:
		kt = spikms.NISTP521ECDHKWType
	case "X25519":
		kt = spikms.X25519ECDHKWType
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return nil, fmt.Errorf("buildJWKKey: marshal key error: %w", err)
	}

	jwkKMSKID, err := jwkkid.CreateKID(mPubKey, kt)
	if err != nil {
		return nil, fmt.Errorf("buildJWKKey: createKID error: %w", err)
	}

	pubKey.KID = jwkKMSKID
	return pubKey, nil
}
