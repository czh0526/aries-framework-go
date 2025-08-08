package anoncrypt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	chacha "golang.org/x/crypto/chacha20poly1305"
)

func (p *Packer) Unpack(envelope []byte) (*transport.Envelope, error) {

	// 拆 Envelope
	var envelopeData legacyEnvelope
	err := json.Unmarshal(envelope, &envelopeData)
	if err != nil {
		return nil, err
	}

	protectedBytes, err := base64.URLEncoding.DecodeString(envelopeData.Protected)
	if err != nil {
		return nil, err
	}

	// 拆 Protected
	var protectedData protected
	err = json.Unmarshal(protectedBytes, &protectedData)
	if err != nil {
		return nil, err
	}

	if protectedData.Typ != encodingType {
		return nil, fmt.Errorf("message type %s not supported", protectedData.Typ)
	}
	if protectedData.Alg != anonCrypt {
		return nil, fmt.Errorf("message alg %s not supported", protectedData.Alg)
	}

	keys, err := getCEK(protectedData.Recipients, p.kms)
	if err != nil {
		return nil, err
	}

	cek, recKey := keys.cek, keys.myKey

	data, err := p.decodeCipherText(cek, &envelopeData)
	if err != nil {
		return nil, err
	}

	return &transport.Envelope{
		Message: data,
		ToKey:   recKey,
	}, nil
}

type keys struct {
	cek   *[chacha.KeySize]byte
	myKey []byte
}

func getCEK(recipients []recipient, km spikms.KeyManager) (*keys, error) {
	var candidateKeys []string

	for _, recipient := range recipients {
		candidateKeys = append(candidateKeys, recipient.Header.KID)
	}

	recKeyIdx, err := findVerKey(km, candidateKeys)
	if err != nil {
		return nil, fmt.Errorf("getCEK: no key accessible: %w", err)
	}

	recip := recipients[recKeyIdx]
	recKey := base58.Decode(recip.Header.KID)

	encCEK, err := base64.URLEncoding.DecodeString(recip.EncryptedKey)
	if err != nil {
		return nil, err
	}

	b, err := newCryptoBox(km)
	if err != nil {
		return nil, err
	}

	cekSlice, err := b.SealOpen(encCEK, recKey)
	if err != nil {
		return nil, fmt.Errorf("getCEK: failed to decrypt CEK: %w", err)
	}

	var cek [chacha.KeySize]byte
	copy(cek[:], cekSlice)

	return &keys{
		cek:   &cek,
		myKey: recKey,
	}, nil
}

func findVerKey(km spikms.KeyManager, candidateKeys []string) (int, error) {
	var errs []error

	for i, key := range candidateKeys {
		recKID, err := jwkkid.CreateKID(base58.Decode(key), spikms.ED25519Type)
		if err != nil {
			return -1, err
		}

		_, err = km.Get(recKID)
		if err == nil {
			return i, nil
		}

		errs = append(errs, err)
	}

	return -1, fmt.Errorf("none of the recipient keys were found in kms: %v", errs)
}
