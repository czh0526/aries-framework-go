package kidresolver

import (
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
)

type KIDResolver interface {
	Resolve(keyID string) (*spicrypto.PublicKey, error)
}
