package kidresolver

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
)

type KIDResolver interface {
	Resolve(keyID string) (*spicrypto.PublicKey, error)
}

type DIDKeyResolver struct{}

func (k *DIDKeyResolver) Resolve(kid string) (*spicrypto.PublicKey, error) {
	return kmsdidkey.EncryptionPubKeyFromDIDKey(kid)
}
