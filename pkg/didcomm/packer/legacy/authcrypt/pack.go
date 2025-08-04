package authcrypt

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

var logger = log.New("aries-framework/pkb/didcomm/packer/legacy")

func (p *Packer) Pack(_contentType string, payload, senderKey []byte, recipientPubKeys [][]byte) (envelope []byte, err error) {
	if len(recipientPubKeys) == 0 {
		return nil, errors.New("empty recipients keys, must have at least one recipient")
	}

	nonce := make([]byte, chacha.NonceSize)
	_, err = p.randSource.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("pack: failed to generate random nonce: %w", err)
	}

	cek := &[chacha.KeySize]byte{}
	_, err = p.randSource.Read(cek[:])
	if err != nil {
		return nil, fmt.Errorf("pack: failed to generate random cek: %w", err)
	}

	var recipients []recipient
	recipients, err = p.buildRecipients(cek, senderKey, recipientPubKeys)
	if err != nil {
		return nil, fmt.Errorf("pack: failed to build recipients: %w", err)
	}

	header := protected{
		Enc:        "chacha20poly1305_ietf",
		Typ:        encodingType,
		Alg:        "Authcrypt",
		Recipients: recipients,
	}

	return p.buildEnvelope(nonce, payload, cek[:], &header)
}

func (p *Packer) buildRecipients(cek *[chacha.KeySize]byte, senderKey []byte, recPubKeys [][]byte) ([]recipient, error) {
	encodedRecipients := make([]recipient, 0)

	for _, recKey := range recPubKeys {
		rec, err := p.buildRecipient(cek, senderKey, recKey)
		if err != nil {
			logger.Warnf("buildRecipients: failed to build recipient: %w", err)
			continue
		}

		encodedRecipients = append(encodedRecipients, *rec)
	}

	if len(encodedRecipients) == 0 {
		return nil, fmt.Errorf("recipients keys are empty")
	}

	return encodedRecipients, nil
}

func (p *Packer) buildRecipient(cek *[chacha.KeySize]byte, senderKey, recKey []byte) (*recipient, error) {
	var nonce [24]byte

	_, err := p.randSource.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to generate random nonce: %w", err)
	}

	senderKID, err := jwkkid.CreateKID(senderKey, spikms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to create KID for sender key: %w", err)
	}

	recEncKey, err := cryptoutil.PublicEd25519toCurve25519(recKey)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to convert public Ed25519 to Curve25519: %w", err)
	}

	box, err := newCryptoBox(p.kms)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to create new CryptoBox: %w", err)
	}
	encCEK, err := box.Easy()

}

func newCryptoBox(km spikms.KeyManager) (kms.CryptoBox, error) {
	switch km.(type) {
	case *localkms.LocalKMS:
		return localkms.NewCryptoBox(km)
	//case *webkms.RemoteKMS:
	default:
		return localkms.NewCryptoBox(km)
	}
}
