package authcrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	comp_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	resolver "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/log"
	docresolver "github.com/czh0526/aries-framework-go/component/models/jose/diddocresolver"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/doc/jose"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"strings"
)

var logger = log.New("aries-framework.pkg/didcomm/packer/authcrypt")

type Packer struct {
	kms           spikms.KeyManager
	encAlg        comp_jose.EncAlg
	cryptoService spicrypto.Crypto
	kidResolvers  []kidresolver.KIDResolver
}

func New(ctx packer.Provider, encAlg comp_jose.EncAlg) (*Packer, error) {
	err := validateEncAlg(encAlg)
	if err != nil {
		return nil, fmt.Errorf("authcrypt: %w", err)
	}

	k := ctx.KMS()
	if k == nil {
		return nil, errors.New("authcrypt: failed to create packer because KMS is empty")
	}

	c := ctx.Crypto()
	if c == nil {
		return nil, errors.New("authcrypt: failed to create packer because crypto service is empty")
	}

	vdrReg := ctx.VDRegistry()
	if vdrReg == nil {
		return nil, errors.New("authcrypt: failed to create packer because vdr registry is empty")
	}

	var kidResolvers []kidresolver.KIDResolver
	kidResolvers = append(kidResolvers,
		&kidresolver.DIDKeyResolver{},
		&docresolver.DIDDocResolver{VDRRegistry: vdrReg})

	return &Packer{
		kms:           k,
		encAlg:        encAlg,
		cryptoService: c,
		kidResolvers:  kidResolvers,
	}, nil
}

func (p *Packer) EncodingType() string {
	return transport.MediaTypeV2EncryptedEnvelope
}

func (p *Packer) Pack(contentType string, payload []byte, senderID []byte, recipientsPubKeys [][]byte) ([]byte, error) {
	if len(recipientsPubKeys) == 0 {
		return nil, fmt.Errorf("authcrypt Pack: empty recipientsPubKeys")
	}

	recECKeys, aad, err := unmarshalRecipientKeys(recipientsPubKeys)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to unmarshal recipient keys: %w", err)
	}

	senderKID := string(senderID)
	skid := senderKID

	if idx := strings.Index(senderKID, "."); idx > 0 {
		senderKID = senderKID[:idx]
		skid = skid[idx+1:]
	}

	kh, err := p.kms.Get(senderKID)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to get sender key from KMS: %w", err)
	}

	sKH, ok := kh.(*keyset.Handle)
	if !ok {
		sKH = nil
	}

	jweEncrypter, err := comp_jose.NewJWEEncrypt(p.encAlg, p.EncodingType(),
		contentType, skid, sKH, recECKeys, p.cryptoService)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to new JWEEncrypt instance: %w", err)
	}

	jwe, err := jweEncrypter.EncryptWithAuthData(payload, aad)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to encrypt payload: %w", err)
	}

	mPh, err := json.Marshal(jwe.ProtectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: %w", err)
	}

	logger.Debugf("protected headers: %s", mPh)

	var s string
	if len(recipientsPubKeys) == 0 {
		s, err = jwe.CompactSerialize(json.Marshal)
	} else {
		s, err = jwe.FullSerialize(json.Marshal)
	}

	if err != nil {
		return nil, fmt.Errorf("authcrypt Pack: failed to serialize JWE message: %w", err)
	}

	return []byte(s), nil
}

func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {
	jwe, _, _, err := deserializeEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize envelope: %w", err)
	}

	for i := range jwe.Recipients {
		var (
			recKey *spicrypto.PublicKey
			pt     []byte
			recKID string
			env    *transport.Envelope
		)

		// 获取公钥
		recKey, recKID, err = p.pubKey(i, jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: %w", err)
		}

		_, err = p.kms.Get(recKey.KID)
		if err != nil {
			if errors.Is(err, kms.ErrKeyNotFound) {
				retriesMsg := ""

				if i < len(jwe.Recipients) {
					retriesMsg = ", will try another recipient"
				}

				logger.Debugf("authcrypt Unpack: recipient keyID not found in KMS: %v%s", recKey.KID, retriesMsg)
				continue
			}

			return nil, fmt.Errorf("authcrypt Unpack: failed to get key from kms: %w", err)
		}

		jweDecrypter := comp_jose.NewJWEDecrypt(p.kidResolvers, p.cryptoService, p.kms)
	}

	return nil, fmt.Errorf("authcrypt Unpack: no matching recipient in envelope")
}

func (p *Packer) pubKey(i int, jwe *comp_jose.JSONWebEncryption) (*spicrypto.PublicKey, string, error) {
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
		return nil, "", fmt.Errorf("failed to resolve recipient key from %s value: %w",
			keySource, err)
	}

	return recKey, kid, nil
}

func validateEncAlg(alg comp_jose.EncAlg) error {
	switch alg {
	case jose.A128CBCHS256, jose.A192CBCHS384, jose.A256CBCHS384, jose.A256CBCHS512, jose.XC20P:
		return nil
	default:
		return fmt.Errorf("unsupported content encryption algorithm: %v", alg)
	}
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

func deserializeEnvelope(envelope []byte) (*comp_jose.JSONWebEncryption, string, string, error) {
	jwe, err := comp_jose.Deserialize(string(envelope))
	if err != nil {
		return nil, "", "", fmt.Errorf("authcrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	typ, _ := jwe.ProtectedHeaders.Type()
	cty, _ := jwe.ProtectedHeaders.ContentType()

	return jwe, typ, cty, nil
}
