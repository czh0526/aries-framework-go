package authcrypt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/czh0526/aries-framework-go/component/log"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
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

	encCEK, err := box.Easy(cek[:], nonce[:], recEncKey, senderKID)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to encrypt CEK: %w", err)
	}

	encSender, err := box.Seal([]byte(base58.Encode(senderKey)), recEncKey, p.randSource)
	if err != nil {
		return nil, fmt.Errorf("buildRecipient: failed to encrypt sender key: %w", err)
	}

	return &recipient{
		EncryptedKey: base64.URLEncoding.EncodeToString(encCEK),
		Header: recipientHeader{
			KID:    base58.Encode(recKey),
			Sender: base64.URLEncoding.EncodeToString(encSender),
			IV:     base64.URLEncoding.EncodeToString(nonce[:]),
		},
	}, nil
}

func (p *Packer) buildEnvelope(nonce, payload, cek []byte, header *protected) ([]byte, error) {
	protectedBytes, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	protectedB64 := base64.URLEncoding.EncodeToString(protectedBytes)

	// 构造
	chachaCipher, err := chacha.New(cek)
	if err != nil {
		return nil, err
	}

	// 加密
	symPld := chachaCipher.Seal(nil, nonce, payload, []byte(protectedB64))

	// 提取 ciphertext + tag
	cipherText := symPld[0 : len(symPld)-poly1305.TagSize]
	tag := symPld[len(symPld)-poly1305.TagSize:]

	// 构造信封
	env := legacyEnvelope{
		Protected:  protectedB64,
		IV:         base64.URLEncoding.EncodeToString(nonce),
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Tag:        base64.URLEncoding.EncodeToString(tag),
	}

	out, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	return out, nil
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
