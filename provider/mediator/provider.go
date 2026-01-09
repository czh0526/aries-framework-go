package mediator

import (
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
)

type Provider interface {
	Service(id string) (interface{}, error)
	KMS() spikms.KeyManager
	ServiceEndpoint() string
	KeyType() spikms.KeyType
	KeyAgreementType() spikms.KeyType
	MediaTypeProfiles() []string
}
