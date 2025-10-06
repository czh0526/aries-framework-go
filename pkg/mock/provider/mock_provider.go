package provider

import (
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries/api"
	"github.com/czh0526/aries-framework-go/pkg/store/did"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

type Provider struct {
	ServiceValue                      interface{}
	ServiceErr                        error
	ServiceMap                        map[string]interface{}
	KMSValue                          spikms.KeyManager
	ServiceEndpointValue              string
	StorageProviderValue              spistorage.Provider
	ProtocolStateStorageProviderValue spistorage.Provider
	DIDConnectionStoreValue           did.ConnectionStore
	PackerList                        []packer.Packer
	PackerValue                       packer.Packer
	CryptoValue                       spicrypto.Crypto
	VDRegistryValue                   vdrapi.Registry
	MessageServiceProviderValue       api.MessageServiceProvider
	InboundMessengerValue             service.InboundMessenger
}

func (p *Provider) KMS() spikms.KeyManager {
	return p.KMSValue
}

func (p *Provider) Crypto() spicrypto.Crypto {
	return p.CryptoValue
}

func (p *Provider) StorageProvider() spistorage.Provider {
	return p.StorageProviderValue
}

func (p *Provider) VDRegistry() vdrapi.Registry {
	return p.VDRegistryValue
}
