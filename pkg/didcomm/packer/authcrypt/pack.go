package authcrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	aries_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
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
	encAlg        aries_jose.EncAlg
	cryptoService spicrypto.Crypto
	kidResolvers  []kidresolver.KIDResolver
}

func New(ctx packer.Provider, encAlg aries_jose.EncAlg) (*Packer, error) {
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

	jweEncrypter, err := aries_jose.NewJWEEncrypt(p.encAlg, p.EncodingType(),
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

		jweDecrypter := aries_jose.NewJWEDecrypt(p.kidResolvers, p.cryptoService, p.kms)

		pt, err = jweDecrypter.Decrypt(jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: failed to decrypt JWE envelope: %w", err)
		}

		env, err = p.buildEnvelope(recKey, recKID, pt, jwe)
		if err != nil {
			return nil, fmt.Errorf("authcrypt Unpack: %w", err)
		}

		return env, nil
	}

	return nil, fmt.Errorf("authcrypt Unpack: no matching recipient in envelope")
}

func (p *Packer) buildEnvelope(recKey *spicrypto.PublicKey, recKID string, message []byte,
	jwe *aries_jose.JSONWebEncryption) (*transport.Envelope, error) {
	recKey.KID = recKID

	ecdh1puPubKeyBytes, err := json.Marshal(recKey)
	if err != nil {
		return nil, fmt.Errorf("buildEnvelope: failed to marshal recipient public key: %w", err)
	}

	mSenderPubKey, err := p.extractSenderKey(jwe)
	if err != nil {
		return nil, err
	}

	return &transport.Envelope{
		Message: message,
		FromKey: mSenderPubKey,
		ToKey:   ecdh1puPubKeyBytes,
	}, nil
}

func (p *Packer) extractSenderKey(jwe *aries_jose.JSONWebEncryption) ([]byte, error) {
	var (
		senderKey     *spicrypto.PublicKey
		mSenderPubKey []byte
		err           error
	)

	skidHeader, ok := jwe.ProtectedHeaders["skid"]
	if ok {
		skid, ok := skidHeader.(string)
		if ok {
			for _, r := range p.kidResolvers {
				senderKey, err = r.Resolve(skid)
				if err != nil {
					logger.Debugf("authcrypt Unpack: unpack successful, but resolving sender key failed [%v] "+
						"using %T resolver, skipping it.", err.Error(), r)
				}

				if senderKey != nil {
					logger.Debugf("authcrypt Unpack: unpack successful with resolving sender key success "+
						"using %T resolver, will be using resolved senderKey for skid: %v", r, skid)
					break
				}
			}

			if senderKey != nil {
				senderKey.KID = skid
				mSenderPubKey, err = json.Marshal(senderKey)

				if err != nil {
					return nil, fmt.Errorf("authcrypt Unpack: failed to marshal sender public key: %w", err)
				}
			} else {
				logger.Debugf("authcrypt Unpack: senderKey not resolved, skipping FromKey in envelope")
			}
		}
	}

	return mSenderPubKey, nil
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
		return nil, "", fmt.Errorf("failed to resolve recipient key from %s value: %w",
			keySource, err)
	}

	return recKey, kid, nil
}

func validateEncAlg(alg aries_jose.EncAlg) error {
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

func deserializeEnvelope(envelope []byte) (*aries_jose.JSONWebEncryption, string, string, error) {
	jwe, err := aries_jose.Deserialize(string(envelope))
	if err != nil {
		return nil, "", "", fmt.Errorf("authcrypt Unpack: failed to deserialize JWE message: %w", err)
	}

	typ, _ := jwe.ProtectedHeaders.Type()
	cty, _ := jwe.ProtectedHeaders.ContentType()

	return jwe, typ, cty, nil
}
