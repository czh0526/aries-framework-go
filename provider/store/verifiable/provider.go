package verifiable

import (
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/piprate/json-gold/ld"
)

type Provider interface {
	StorageProvider() spistorage.Provider
	JSONLDDocumentLoader() ld.DocumentLoader
}
