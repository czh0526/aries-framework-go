package outofband

import spikms "github.com/czh0526/aries-framework-go/spi/kms"

type Provider interface {
	ServiceEndpoint() string
	Service(id string) (interface{}, error)
	KMS() spikms.KeyManager
	KeyType() spikms.KeyType
	KeyAgreementType() spikms.KeyType
	MediaTypeProfiles() []string
}
