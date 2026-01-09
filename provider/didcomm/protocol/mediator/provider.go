package mediator

import (
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() spistorage.Provider
	ProtocolStateStorageProvider() spistorage.Provider
	RouterEndpoint() string
	KMS() spikms.KeyManager
	VDRegistry() vdrapi.Registry
	Service(id string) (interface{}, error)
	KeyAgreementType() spikms.KeyType
	MediaTypeProfiles() []string
}
