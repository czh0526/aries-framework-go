package localkms

import (
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/kms/localkms"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

func NewCryptoBox(km spikms.KeyManager) (kms.CryptoBox, error) {
	return localkms.NewCryptoBox(km)
}
