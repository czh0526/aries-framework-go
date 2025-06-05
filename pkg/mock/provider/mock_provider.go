package provider

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/store/did"
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
	OutboundDispatcherValue           dispatcher.Outbound
}
