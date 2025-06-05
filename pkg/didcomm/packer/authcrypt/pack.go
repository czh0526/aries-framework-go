package authcrypt

import (
	"errors"
	"fmt"
	comp_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	docresolver "github.com/czh0526/aries-framework-go/component/models/jose/diddocresolver"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/doc/jose"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

type Packer struct {
	kms           spikms.KeyManager
	encAlg        comp_jose.EncAlg
	cryptoService spicrypto.Crypto
	kidResolvers  []kidresolver.KIDResolver
}

func New(ctx packer.Provider, encAlg comp_jose.EncAlg) (*Packer, error) {
	err := validateEncAlg(encAlg)
	if err != nil {
		return nil, fmt.Errorf("authcrypt: %v", err)
	}

	k := ctx.KMS()
	if k == nil {
		return nil, errors.New("authcrypt: failed to create packer because KMS is empty")
	}

	c := ctx.Crypto()
	if c == nil {
		return nil, errors.New("authcrypt: failed to create packer because crypto service is empty")
	}

	vdrReg := ctx.VDRegistry()
	if vdrReg == nil {
		return nil, errors.New("authcrypt: failed to create packer because vdr registry is empty")
	}

	var kidResolvers []kidresolver.KIDResolver
	kidResolvers = append(kidResolvers,
		&kidresolver.DIDKeyResolver{},
		&docresolver.DIDDocResolver{VDRRegistry: vdrReg})

	return &Packer{
		kms:           k,
		encAlg:        encAlg,
		cryptoService: c,
		kidResolvers:  kidResolvers,
	}, nil
}

func validateEncAlg(alg comp_jose.EncAlg) error {
	switch alg {
	case jose.A128CBCHS256, jose.A192CBCHS384, jose.A256CBCHS384, jose.A256CBCHS512, jose.XC20P:
		return nil
	default:
		return fmt.Errorf("unsupported content encryption algorithm: %v", alg)
	}
}
