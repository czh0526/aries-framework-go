package localkms

import (
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"log"
)

type LocalKMS struct {
}

// New returns a new instance of a local KMS.
func New(primaryKeyURI string, p spikms.Provider) (*LocalKMS, error) {
	log.Printf("【default】New LocalKMS")
	return &LocalKMS{}, nil
}
