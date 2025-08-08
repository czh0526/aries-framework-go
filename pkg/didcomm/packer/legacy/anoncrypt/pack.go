package anoncrypt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/czh0526/aries-framework-go/component/log"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

var logger = log.New("aries-framework/pkg/didcomm/packer/legacy/anoncrypt")

func (p *Packer) Pack(_ string, payload, _ []byte, recipientPubKeys [][]byte) ([]byte, error) {
	var err error

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
		return nil, fmt.Errorf("pack: failed to generate cek: %w", err)
	}

	var recipients []recipient
	recipients, err = p.buildRecipients(cek, recipientPubKeys)

	header := protected{
		Enc:        anonCryptEncType,
		Typ:        encodingType,
		Alg:        anonCrypt,
		Recipients: recipients,
	}

	return p.buildEnvelope(nonce, payload, cek[:], &header)
}

func (p *Packer) buildRecipients(cek *[chacha.KeySize]byte, recPubKeys [][]byte) ([]recipient, error) {
	encodedRecipients := make([]recipient, 0)

	for _, recKey := range recPubKeys {
		rec, err := p.buildRecipient(cek, recKey)
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

func (p *Packer) buildRecipient(cek *[chacha.KeySize]byte, recKey []byte) (*recipient, error) {
	recEncKey, err := cryptoutil.PublicEd25519toCurve25519(recKey)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to convert public Ed25519 to Curve25519: %w", err)
	}

	box, err := newCryptoBox(p.kms)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to encrypt cek: %w", err)
	}

	encCEK, err := box.Seal(cek[:], recEncKey, p.randSource)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to encrypt cek: %w", err)
	}

	return &recipient{
		EncryptedKey: base64.URLEncoding.EncodeToString(encCEK),
		Header: recipientHeader{
			KID: base58.Encode(recKey),
		},
	}, nil
}

func (p *Packer) buildEnvelope(nonce, payload, cek []byte, header *protected) ([]byte, error) {
	protectedBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	protectedB64 := base64.URLEncoding.EncodeToString(protectedBytes)

	chachaCipher, err := chacha.New(cek)
	if err != nil {
		return nil, err
	}

	symPld := chachaCipher.Seal(nil, nonce, payload, []byte(protectedB64))

	cipherText := symPld[0 : len(symPld)-poly1305.TagSize]
	tag := symPld[len(symPld)-poly1305.TagSize:]

	env := legacyEnvelope{
		Protected:  protectedB64,
		IV:         base64.URLEncoding.EncodeToString(nonce),
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Tag:        base64.URLEncoding.EncodeToString(tag),
	}

	out, err := json.Marshal(&env)
	if err != nil {
		return nil, err
	}

	return out, nil
}
