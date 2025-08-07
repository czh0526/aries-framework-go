package localkms

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms/internal/keywrapper"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/util/cryptoutil"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/golang/protobuf/proto"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"golang.org/x/crypto/nacl/box"
	"io"
)

type CryptoBox struct {
	km *LocalKMS
}

func (b *CryptoBox) Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error) {
	// 准备对端的公钥数据
	var recPubBytes [cryptoutil.Curve25519KeySize]byte
	copy(recPubBytes[:], theirPub)

	// 导出本人的私钥
	senderPriv, err := b.km.exportEncPrivKeyBytes(myKID)
	if err != nil {
		return nil, fmt.Errorf("easy: failed to export sender key: %w, kid: %v", err, myKID)
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	// 准备本人的私钥数据
	copy(priv[:], senderPriv)
	// 准备 nonce 数据
	copy(nonceBytes[:], nonce)

	// 信息封包
	ret := box.Seal(nil, payload, &nonceBytes, &recPubBytes, &priv)

	return ret, nil
}

func (b *CryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	var sendPubBytes [cryptoutil.Curve25519KeySize]byte
	copy(sendPubBytes[:], theirPub)

	kid, err := jwkkid.CreateKID(myPub, spikms.ED25519Type)
	if err != nil {
		return nil, err
	}

	senderPriv, err := b.km.exportEncPrivKeyBytes(kid)
	if err != nil {
		return nil, err
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], senderPriv)
	copy(nonceBytes[:], nonce)

	out, success := box.Open(nil, cipherText, &nonceBytes, &sendPubBytes, &priv)
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}

func (b *CryptoBox) Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error) {
	epk, esk, err := box.GenerateKey(randSource)
	if err != nil {
		return nil, err
	}

	var recPubBytes [cryptoutil.Curve25519KeySize]byte
	copy(recPubBytes[:], theirEncPub)

	nonce, err := cryptoutil.Nonce(epk[:], theirEncPub)
	if err != nil {
		return nil, err
	}

	ret := box.Seal(epk[:], payload, nonce, &recPubBytes, esk)

	return ret, nil
}

func (b *CryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	if len(cipherText) < cryptoutil.Curve25519KeySize {
		return nil, errors.New("ciphertext too short")
	}

	kid, err := jwkkid.CreateKID(myPub, spikms.ED25519Type)
	if err != nil {
		return nil, fmt.Errorf("sealOpen: failed to compute ED25519 kid: %w", err)
	}

	recipientEncPriv, err := b.km.exportEncPrivKeyBytes(kid)
	if err != nil {
		return nil, fmt.Errorf("sealOpen: failed to exportPrivKeyBytes: %w", err)
	}

	var (
		epk  [cryptoutil.Curve25519KeySize]byte
		priv [cryptoutil.Curve25519KeySize]byte
	)

	copy(epk[:], cipherText[:cryptoutil.Curve25519KeySize])
	copy(priv[:], recipientEncPriv)

	recEncPub, err := cryptoutil.PublicEd25519toCurve25519(myPub)
	if err != nil {
		return nil, fmt.Errorf("sealOpen: failed to convert pub Ed25519 to X25519 key: %w", err)
	}

	nonce, err := cryptoutil.Nonce(epk[:], recEncPub)
	if err != nil {
		return nil, err
	}

	out, success := box.Open(nil, cipherText[cryptoutil.Curve25519KeySize:], nonce, &epk, &priv)
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}

var _ kms.CryptoBox = (*CryptoBox)(nil)

func NewCryptoBox(km spikms.KeyManager) (*CryptoBox, error) {
	lkms, ok := km.(*LocalKMS)
	if !ok {
		return nil, fmt.Errorf("cannot use parameter argument as KMS")
	}

	return &CryptoBox{km: lkms}, nil
}

func (l *LocalKMS) exportEncPrivKeyBytes(id string) ([]byte, error) {
	kh, err := l.getKeySet(id)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	bWriter := keyset.NewBinaryWriter(buf)

	kw, err := keywrapper.New(&noop.NoLock{}, "local-lock://tmp")
	if err != nil {
		return nil, err
	}

	primaryKeyEnvAEAD := aead.NewKMSEnvelopeAEAD2(aead.AES256GCMKeyTemplate(), kw)

	err = kh.Write(bWriter, primaryKeyEnvAEAD)
	if err != nil {
		return nil, err
	}

	encryptedKS := &tinkpb.EncryptedKeyset{}
	err = proto.Unmarshal(buf.Bytes(), encryptedKS)
	if err != nil {
		return nil, err
	}

	decryptedKS, err := primaryKeyEnvAEAD.Decrypt(encryptedKS.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, err
	}

	return extractPrivKey(decryptedKS)
}

func extractPrivKey(marshalledKeySet []byte) ([]byte, error) {
	ks := &tinkpb.Keyset{}
	err := proto.Unmarshal(marshalledKeySet, ks)
	if err != nil {
		return nil, err
	}

	for _, key := range ks.Key {
		if key.KeyId != ks.PrimaryKeyId || key.Status != tinkpb.KeyStatusType_ENABLED {
			continue
		}

		prvKey := &ed25519pb.Ed25519PrivateKey{}
		err = proto.Unmarshal(key.KeyData.Value, prvKey)
		if err != nil {
			return nil, err
		}

		pkBytes := make([]byte, ed25519.PrivateKeySize)
		copy(pkBytes[:ed25519.PublicKeySize], prvKey.KeyValue)
		copy(pkBytes[ed25519.PublicKeySize:], prvKey.PublicKey.KeyValue)

		return cryptoutil.SecretEd25519toCurve25519(pkBytes)
	}

	return nil, errors.New("private key not found")
}
