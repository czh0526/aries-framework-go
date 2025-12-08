package verifiable

import (
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
)

type Provider interface {
	StorageProvider() spistorage.Provider
	VDRegistry() vdrapi.Registry
	KMS() spikms.KeyManager
	Crypto() spicrypto.Crypto
	JSONLDDocumentLoader() ld.DocumentLoader
}
