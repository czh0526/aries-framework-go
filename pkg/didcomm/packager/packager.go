package packager

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"strings"
)

const (
	authSuffix = "authcrypt"
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
		return nil, fmt.Errorf("packMessage: %v", err)
	}

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

func (p *Packager) prepareSendAndRecipientKeys(cty string, envelope *transport.Envelope) ([]byte, [][]byte, error) {

	var recipients [][]byte
	isLegacy := isMediaTypeForLegacyPacker(cty)
	for i, receiverKeyID := range envelope.ToKeys {
		switch {
		case strings.HasPrefix(receiverKeyID, "did:key"):
			marshalledKey, err := addDidKeyToRecipients(i, receiverKeyID, isLegacy)
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
	case strings.HasPrefix(string(envelope.FromKey), "did:key"):
		senderKey, err := kmsdidkey.EncryptionPubKeyFromDIDKey(string(envelope.FromKey))
	case strings.Index(string(envelope.FromKey), "#") > 0:
	default
	}
}

func (p *Packager) resolveKeyAgreementFromDIDDoc(keyAgrID string) (*spicrypto.PublicKey, error) {

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
