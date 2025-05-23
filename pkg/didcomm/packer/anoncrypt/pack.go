package anoncrypt

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	resolver "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

type Packer struct {
	kms           spikms.KeyManager
	encAlg        jose.EncAlg
	cryptoService spicrypto.Crypto
	kidResolvers  []resolver.KIDResolver
}

func New(ctx packer.Provider, encAlg jose.EncAlg) (*Packer, error) {
	return &Packer{}, nil
}

func (p *Packer) EncodingType() string {
	return transport.MediaTypeV2EncryptedEnvelope
}
