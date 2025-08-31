package anoncrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	kmsapi "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	aries_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	resolver "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"strings"
)

var logger = log.New("aries-framework/pkg/didcomm/packer/anoncrypt")

type Packer struct {
	kms           spikms.KeyManager
	encAlg        jose.EncAlg
	cryptoService spicrypto.Crypto
	kidResolvers  []resolver.KIDResolver
}

func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {
	k := ctx.KMS()
	if k == nil {
		return nil, errors.New("anoncrypt: failed to create packer because KMS is empty")
	}

	c := ctx.Crypto()
	if c == nil {
		return nil, errors.New("anoncrypt: failed to create packer because Crypto is empty")
	}

	var kidResolvers []resolver.KIDResolver
	kidResolvers = append(kidResolvers,
		&resolver.DIDKeyResolver{},
		//&resolver.DIDDocResolver{VDRegistry: vdrReg},
	)

	return &Packer{
		kms:           k,
		encAlg:        encAlg,
		cryptoService: c,
		kidResolvers:  kidResolvers,
	}, nil
}

func (p *Packer) Pack(contentType string, payload, _ []byte, recipientsPubKeys [][]byte) ([]byte, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("anoncrypt Pack: empty recipientsPubKeys")
	}

	recECKeys, aad, err := unmarshalRecipientKeys(recipientsPubKeys)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to convert recipient keys: %w", err)
	}

	jweEncrypter, err := aries_jose.NewJWEEncrypt(p.encAlg, p.EncodingType(), contentType,
		"", nil, recECKeys, p.cryptoService)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to create JWEEncrypter instance: %w", err)
	}

	jwe, err := jweEncrypter.EncryptWithAuthData(payload, aad)
	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to encrypt payload: %w", err)
	}

	var s string
	if len(recipientsPubKeys) == 0 {
		s, err = jwe.CompactSerialize(json.Marshal)
	} else {
		s, err = jwe.FullSerialize(json.Marshal)
	}

	if err != nil {
		return nil, fmt.Errorf("anoncrypt Pack: failed to serialize JWE message: %w", err)
	}

	return []byte(s), nil
}

func unmarshalRecipientKeys(keys [][]byte) ([]*spicrypto.PublicKey, []byte, error) {
	var (
		pubKeys []*spicrypto.PublicKey
		aad     []byte
	)

	for _, key := range keys {
		var ecKey *spicrypto.PublicKey

		err := json.Unmarshal(key, &ecKey)
		if err != nil {
			return nil, nil, err
		}

		pubKeys = append(pubKeys, ecKey)
	}

	return pubKeys, aad, nil
}

func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {
	jwe, _, _, err := deserializeEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize JWE envelope: %w", err)
	}

	for i := range jwe.Recipients {
		recKey, recKID, err := p.pubKey(i, jwe)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize JWE envelope: %w", err)
		}

		_, err = p.kms.Get(recKey.KID)
		if err != nil {
			if errors.Is(err, kmsapi.ErrKeyNotFound) {
				retriesMsg := ""

				if i < len(jwe.Recipients) {
					retriesMsg = ", will try another recipient"
				}

				logger.Debugf("anoncrypt Unpack: recipient keyID not found in KMS: %v%s", recKey.KID, retriesMsg)

				continue
			}

			return nil, fmt.Errorf("anoncrypt Unpack: failed to get key from kms: %w", err)
		}

		jweDecrypter := aries_jose.NewJWEDecrypt(p.kidResolvers, p.cryptoService, p.kms)

		pt, err := jweDecrypter.Decrypt(jwe)
		if err != nil {
			return nil, fmt.Errorf("anoncrypt Unpack: failed to decrypt JWE envelope: %w", err)
		}

		recKey.KID = recKID
		ecdhesPubKeyBytes, err := json.Marshal(recKey)
		if err != nil {
			return nil, fmt.Errorf("anoncrypt Unpack: failed to marshal public key: %w", err)
		}

		return &transport.Envelope{
			Message: pt,
			ToKey:   ecdhesPubKeyBytes,
		}, nil
	}

	return nil, fmt.Errorf("anoncrypt Unpack: no matching recipient in envelope")
}

func deserializeEnvelope(envelope []byte) (*jose.JSONWebEncryption, string, string, error) {
	jwe, err := jose.Deserialize(string(envelope))
	if err != nil {
		return nil, "", "", fmt.Errorf("anoncrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	typ, _ := jwe.ProtectedHeaders.Type()
	cty, _ := jwe.ProtectedHeaders.ContentType()

	return jwe, typ, cty, nil
}

func (p *Packer) pubKey(i int, jwe *aries_jose.JSONWebEncryption) (*spicrypto.PublicKey, string, error) {
	var (
		kid         string
		kidResolver resolver.KIDResolver
	)

	if i == 0 && len(jwe.Recipients) == 1 {
		var ok bool
		kid, ok = jwe.ProtectedHeaders.KeyID()
		if !ok {
			return nil, "", fmt.Errorf("single recipient missing 'KID' in jwe.ProtectHeaders")
		}
	} else {
		kid = jwe.Recipients[i].Header.KID
	}

	keySource := "did:key"

	switch {
	case strings.HasPrefix(kid, keySource):
		kidResolver = p.kidResolvers[0]
	case strings.Index(kid, "#") > 0:
		kidResolver = p.kidResolvers[1]
		keySource = "didDoc.KeyAgreement[].VerificationMethod.ID"
	default:
		return nil, "", fmt.Errorf("invalid kid format, must be a did:key or a DID doc verificationMethod ID")
	}

	recKey, err := kidResolver.Resolve(kid)
	if err != nil {
		return nil, "", fmt.Errorf("anoncrypt Unpack: failed to resolve recipient key from %s value: %w",
			keySource, err)
	}

	return recKey, kid, nil
}

func (p *Packer) EncodingType() string {
	return transport.MediaTypeV2EncryptedEnvelope
}
