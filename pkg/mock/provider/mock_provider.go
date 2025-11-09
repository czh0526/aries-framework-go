package provider

import (
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
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
	PackagerValue                     transport.Packager
	OutboundDispatcherValue           dispatcher.Outbound
	CryptoValue                       spicrypto.Crypto
	VDRegistryValue                   vdrapi.Registry
	MessageServiceProviderValue       api.MessageServiceProvider
	InboundMessageHandlerValue        transport.InboundMessageHandler
	InboundMessengerValue             service.InboundMessenger
}

func (p *Provider) ProtocolStateStorageProvider() spistorage.Provider {
	return p.ProtocolStateStorageProviderValue
}

func (p *Provider) OutboundDispatcher() dispatcher.Outbound {
	return p.OutboundDispatcherValue
}

func (p *Provider) InboundMessageHandler() transport.InboundMessageHandler {
	return p.InboundMessageHandlerValue
}

func (p *Provider) Packager() transport.Packager {
	return p.PackagerValue
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
