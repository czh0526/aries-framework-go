package authcrypt

import (
	"encoding/json"
	"errors"
	"fmt"
	comp_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	docresolver "github.com/czh0526/aries-framework-go/component/models/jose/diddocresolver"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/doc/jose"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"strings"
)

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

	jwe, err := jweEncrypter.EncryptWithAuthData()
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
