package context

import (
	"fmt"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
)

type Provider struct {
	kms                 spikms.KeyManager
	crypto              spicrypto.Crypto
	storeProvider       spistorage.Provider
	contextStore        ldstore.ContextStore
	remoteProviderStore ldstore.RemoteProviderStore
	documentLoader      jsonld.DocumentLoader
}

func (p *Provider) StorageProvider() spistorage.Provider {
	return p.storeProvider
}

func (p *Provider) JSONLDContextStore() ldstore.ContextStore {
	return p.contextStore
}

func (p *Provider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.remoteProviderStore
}

type ProviderOption func(provider *Provider) error

func New(opts ...ProviderOption) (*Provider, error) {
	provider := Provider{}

	for _, option := range opts {
		err := option(&provider)
		if err != nil {
			return nil, fmt.Errorf("option failed: %v", err)
		}
	}

	return &provider, nil
}

func WithKMS(k spikms.KeyManager) ProviderOption {
	return func(p *Provider) error {
		p.kms = k
		return nil
	}
}

func WithCrypto(c spicrypto.Crypto) ProviderOption {
	return func(p *Provider) error {
		p.crypto = c
		return nil
	}
}

func WithStorageProvider(sp spistorage.Provider) ProviderOption {
	return func(p *Provider) error {
		p.storeProvider = sp
		return nil
	}
}

func WithJSONLDContextStore(store ldstore.ContextStore) ProviderOption {
	return func(p *Provider) error {
		p.contextStore = store
		return nil
	}
}

func WithJSONLDRemoteProviderStore(store ldstore.RemoteProviderStore) ProviderOption {
	return func(p *Provider) error {
		p.remoteProviderStore = store
		return nil
	}
}

func WithJSONLDDocumentLoader(loader jsonld.DocumentLoader) ProviderOption {
	return func(p *Provider) error {
		p.documentLoader = loader
		return nil
	}
}
