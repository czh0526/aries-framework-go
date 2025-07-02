package packager

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"log"
	"strings"
)

const (
	authSuffix                 = "authcrypt"
	jsonWebKey2020             = "jsonWebKey2020"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

type Provider interface {
	Packers() []packer.Packer
	PrimaryPacker() packer.Packer
	VDRegistry() vdrapi.Registry
}

type Packager struct {
	primaryPacker packer.Packer
	packers       map[string]packer.Packer
	vdrRegistry   vdrapi.Registry
}

func (p *Packager) PackMessage(envelope *transport.Envelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("envelope argument is nil")
	}

	cty, pack, err := p.getCTYAndPacker(envelope)
	if err != nil {
		return nil, fmt.Errorf("packMessage: %w", err)
	}

	senderKey, recipients, err := p.prepareSenderAndRecipientKeys(cty, envelope)
	if err != nil {
		return nil, fmt.Errorf("packMessage: %w", err)
	}

	marshalledEnvelope, err := pack.Pack(cty, envelope.Message, senderKey, recipients)
	if err != nil {
		return nil, fmt.Errorf("packMessage: failed to pack: %w", err)
	}

	return marshalledEnvelope, nil
}

func (p *Packager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Packager) getCTYAndPacker(envelope *transport.Envelope) (string, packer.Packer, error) {
	switch envelope.MediaTypeProfile {
	case transport.MediaTypeAIP2RFC0019Profile,
		transport.MediaTypeProfileDIDCommAIP1:
		packerName := addAuthcryptSuffix(envelope.FromKey, transport.MediaTypeRFC0019EncryptedEnvelope)
		return transport.MediaTypeRFC0019EncryptedEnvelope, p.packers[packerName], nil

	case transport.MediaTypeRFC0019EncryptedEnvelope,
		transport.LegacyDIDCommV1Profile:
		packerName := addAuthcryptSuffix(envelope.FromKey, transport.MediaTypeRFC0019EncryptedEnvelope)
		return envelope.MediaTypeProfile, p.packers[packerName], nil

	case transport.MediaTypeV2EncryptedEnvelope,
		transport.MediaTypeV2PlaintextPayload,
		transport.MediaTypeDIDCommV2Profile,
		transport.MediaTypeAIP2RFC0587Profile:
		packerName := addAuthcryptSuffix(envelope.FromKey, transport.MediaTypeV2EncryptedEnvelope)
		return transport.MediaTypeV2PlaintextPayload, p.packers[packerName], nil

	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
		transport.MediaTypeV1PlaintextPayload:
		packerName := addAuthcryptSuffix(envelope.FromKey, transport.MediaTypeV2EncryptedEnvelope)
		return transport.MediaTypeV1PlaintextPayload, p.packers[packerName], nil

	default:
		if p.primaryPacker != nil {
			return p.primaryPacker.EncodingType(), p.primaryPacker, nil
		}
	}

	return "", nil, fmt.Errorf("no packer found for mediatype profile: '%v'", envelope.MediaTypeProfile)
}

func addAuthcryptSuffix(fromKey []byte, packerName string) string {
	if len(fromKey) > 0 {
		packerName = authSuffix
	}
	return packerName
}

func (p *Packager) prepareSenderAndRecipientKeys(cty string, envelope *transport.Envelope) ([]byte, [][]byte, error) {
	var recipients [][]byte

	isLegacy := isMediaTypeForLegacyPacker(cty)
	for i, receiverKeyID := range envelope.ToKeys {
		switch {
		case strings.HasPrefix(receiverKeyID, "did:key:"):
			marshalledKey, err := addDIDKeyToRecipients(i, receiverKeyID, isLegacy)
			if err != nil {
				return nil, nil, err
			}

			recipients = append(recipients, marshalledKey)

		case strings.Index(receiverKeyID, "#") > 0:
			receiverKey, err := p.resolveKeyAgreementFromDIDDoc(receiverKeyID)
			if err != nil {
				return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for recipient %d: %s", i+1, err)
			}

			if isLegacy {
				recipients = append(recipients, receiverKey.X)
			} else {
				marshalledKey, err := json.Marshal(receiverKey)
				if err != nil {
					return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for recipient %d: %s", i+1, err)
				}
				recipients = append(recipients, marshalledKey)
			}

		case cty == transport.LegacyDIDCommV1Profile:
			recipients = append(recipients, base58.Decode(receiverKeyID))

		default:
			recipients = append(recipients, []byte(receiverKeyID))
		}
	}

	var senderKID []byte
	switch {
	case strings.HasPrefix(string(envelope.FromKey), "did:key:"):
		senderKey, err := kmsdidkey.EncryptionPubKeyFromDIDKey(string(envelope.FromKey))
		if err != nil {
			return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: failed to extract pubKeyBytess from senderVerKey: %s", err)
		}

		if isLegacy {
			senderKID = senderKey.X
		} else {
			senderKID = buildSenderKID(senderKey, envelope)
		}

	case strings.Index(string(envelope.FromKey), "#") > 0:
		senderKey, err := p.resolveKeyAgreementFromDIDDoc(string(envelope.FromKey))
		if err != nil {
			return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for sender: %w", err)
		}

		if isLegacy {
			senderKID = senderKey.X
		} else {
			marshalledSenderKey, err := json.Marshal(senderKey)
			if err != nil {
				return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: marshal sender key: %w", err)
			}

			senderKMSKID, err := jwkkid.CreateKID(marshalledSenderKey, getKMSKeyType(senderKey.Type, senderKey.Curve))
			if err != nil {
				return nil, nil, fmt.Errorf("prepareSenderAndRecipientKeys: for sender KMS KID: %w", err)
			}

			senderKey.KID = senderKMSKID
			senderKID = buildSenderKID(senderKey, envelope)
		}

	default:
		senderKID = envelope.FromKey
	}

	return senderKID, recipients, nil
}

func addDIDKeyToRecipients(i int, receiverKey string, isLegacy bool) ([]byte, error) {
	recKey, err := kmsdidkey.EncryptionPubKeyFromDIDKey(receiverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key bytes from did:key verKey for recipient %d: %w", i+1, err)
	}

	if isLegacy {
		return recKey.X, nil
	}

	recKey.KID = receiverKey
	marshalledKey, err := json.Marshal(recKey)
	if err != nil {
		return nil, fmt.Errorf("prepareSenderAndRecipientKeys: for recipient %d did:key: marshal: %w", i+1, err)
	}

	return marshalledKey, nil
}

func (p *Packager) resolveKeyAgreementFromDIDDoc(keyAgrID string) (*spicrypto.PublicKey, error) {
	i := strings.Index(keyAgrID, "#")

	keyAgrDID := keyAgrID[:i]
	keyAgrFragment := keyAgrID[i+1:]

	docResolution, err := p.vdrRegistry.Resolve(keyAgrDID)
	if err != nil {
		return nil, fmt.Errorf("reolveKeyAgreementFromDIDDoc: for recipient DID doc resolution %w", err)
	}

	for j, ka := range docResolution.DIDDocument.KeyAgreement {
		kaID := ka.VerificationMethod.ID[strings.Index(ka.VerificationMethod.ID, "#")+1:]
		if strings.EqualFold(kaID, keyAgrFragment) {
			return marshalKeyFromVerificationMethod(keyAgrID, &ka.VerificationMethod, j)
		}

		log.Printf("skipping keyID %s since it's not found in didDoc.KeyAgreement of did %s", kaID, keyAgrDID)
	}

	for j := range docResolution.DIDDocument.VerificationMethod {
		vm := &docResolution.DIDDocument.VerificationMethod[j]
		vmID := vm.ID[strings.Index(vm.ID, "#")+i:]
		log.Printf("vm: %#v", vm)

		if strings.EqualFold(vmID, keyAgrFragment) {
			return marshalKeyFromVerificationMethod(keyAgrID, vm, j)
		}
	}

	return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: keyAgreement ID '%s' not found in DID '%s'",
		keyAgrID, docResolution.DIDDocument.ID)
}

func marshalKeyFromVerificationMethod(keyAgrID string, vm *did.VerificationMethod, i int) (*spicrypto.PublicKey, error) {
	var (
		recKey *spicrypto.PublicKey
		err    error
	)

	switch vm.Type {
	case jsonWebKey2020:
		jwkKey := vm.JSONWebKey()
		recKey, err = jwksupport.PublicKeyFromJWK(jwkKey)
		if err != nil {
			return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: for recipient JWK to PubKey %d: %w", i+1, err)
		}

		recKey.KID = keyAgrID

	case x25519KeyAgreementKey2019:
		recKey = &spicrypto.PublicKey{
			KID:   keyAgrID,
			X:     vm.Value,
			Curve: "X25519",
			Type:  "OKP",
		}

	case ed25519VerificationKey2018:
		recKey = &spicrypto.PublicKey{
			KID:   keyAgrID,
			X:     vm.Value,
			Curve: "Ed25519",
			Type:  "OKP",
		}

	default:
		return nil, fmt.Errorf("resolveKeyAgreementFromDIDDoc: invalid KeyAgreement type %d: %s", i+1,
			vm.Type)
	}

	return recKey, nil
}

type Creator func(p Provider) (transport.Packager, error)

func New(p Provider) (*Packager, error) {
	basePackager := Packager{
		primaryPacker: nil,
		packers:       map[string]packer.Packer{},
		vdrRegistry:   p.VDRegistry(),
	}

	basePackager.primaryPacker = p.PrimaryPacker()
	if basePackager.primaryPacker == nil {
		return nil, fmt.Errorf("need primary packer to initialize packager")
	}

	basePackager.addPacker(basePackager.primaryPacker)

	return &basePackager, nil
}

func (p *Packager) addPacker(pack packer.Packer) {
	packerID := pack.EncodingType()

	if p.packers[packerID] == nil {
		p.packers[packerID] = pack
	}
}

func isMediaTypeForLegacyPacker(cty string) bool {
	var isLegacy bool

	switch cty {
	case transport.MediaTypeRFC0019EncryptedEnvelope,
		transport.MediaTypeAIP2RFC0019Profile,
		transport.MediaTypeProfileDIDCommAIP1,
		transport.LegacyDIDCommV1Profile:
		isLegacy = true
	default:
		isLegacy = false
	}

	return isLegacy
}

func getKMSKeyType(keyType, curve string) spikms.KeyType {
	switch keyType {
	case "EC":
		switch curve {
		case "P-256":
			return spikms.NISTP256ECDHKWType
		case "P-384":
			return spikms.NISTP384ECDHKWType
		case "P-521":
			return spikms.NISTP521ECDHKWType
		}
	case "OKP":
		return spikms.X25519ECDHKWType
	}
	return ""
}

func buildSenderKID(senderPubKey *spicrypto.PublicKey, envelopeSenderKey *transport.Envelope) []byte {
	senderKey := []byte(senderPubKey.KID + ".")
	senderKey = append(senderKey, envelopeSenderKey.FromKey...)

	return senderKey
}
