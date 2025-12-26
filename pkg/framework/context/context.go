package context

import (
	"fmt"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher/inbound"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries/api"
	"github.com/czh0526/aries-framework-go/pkg/store/did"
	"github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	jsonld "github.com/piprate/json-gold/ld"
)

type InboundEnvelopeHandler interface {
	HandleInboundEnvelope(envelope *transport.Envelope) error
	HandlerFunc() transport.InboundMessageHandler
}

type Context struct {
	services                   []dispatcher.ProtocolService
	servicesMsgTypeTargets     []dispatcher.MessageTypeTarget
	transportReturnRoute       string
	kms                        spikms.KeyManager
	keyType                    spikms.KeyType
	keyAgreementType           spikms.KeyType
	secretLock                 spisecretlock.Service
	crypto                     spicrypto.Crypto
	storeProvider              spistorage.Provider
	protocolStateStoreProvider spistorage.Provider
	contextStore               ldstore.ContextStore
	verifiableStore            verifiable.Store
	didConnectionStore         did.ConnectionStore
	remoteProviderStore        ldstore.RemoteProviderStore
	documentLoader             jsonld.DocumentLoader
	serviceEndpoint            string
	routerEndpoint             string
	vdr                        vdrapi.Registry
	frameworkID                string
	packager                   transport.Packager
	outboundDispatcher         dispatcher.Outbound
	outboundTransports         []transport.OutboundTransport
	inboundEnvelopeHandler     InboundEnvelopeHandler
	messenger                  service.Messenger
	mediaTypeProfiles          []string
	didRotator                 *middleware.DIDCommMessageMiddleware
}

func (c *Context) JSONLDDocumentLoader() jsonld.DocumentLoader {
	return c.documentLoader
}

type inboundHandler struct {
	handlers []dispatcher.ProtocolService
}

func (ih *inboundHandler) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	for _, h := range ih.handlers {
		if h.Accept(msg.Type()) {
			return h.HandleInbound(msg, ctx)
		}
	}

	return "", fmt.Errorf("no inbound handlers for msg type: %s", msg.Type())
}

func (c *Context) InboundDIDCommMessageHandler() func() service.InboundHandler {
	return func() service.InboundHandler {
		tmp := make([]dispatcher.ProtocolService, len(c.services))
		copy(tmp, c.services)

		return &inboundHandler{
			handlers: tmp,
		}
	}
}

func (c *Context) Messenger() service.Messenger {
	return c.messenger
}

func (c *Context) Service(id string) (interface{}, error) {
	for _, v := range c.services {
		if v.Name() == id {
			return v, nil
		}
	}

	return nil, api.ErrSvcNotFound
}

func (c *Context) SecretLock() spisecretlock.Service {
	return c.secretLock
}

func (c *Context) ServiceEndpoint() string {
	return c.serviceEndpoint
}

func (c *Context) RouterEndpoint() string {
	return c.routerEndpoint
}

func (c *Context) VerifiableStore() verifiable.Store {
	return c.verifiableStore
}

func (c *Context) DIDConnectionStore() did.ConnectionStore {
	return c.didConnectionStore
}

func (c *Context) KeyType() spikms.KeyType {
	return c.keyType
}

func (c *Context) ServiceMsgTypeTargets() []dispatcher.MessageTypeTarget {
	return c.servicesMsgTypeTargets
}

func (c *Context) OutboundTransports() []transport.OutboundTransport {
	return c.outboundTransports
}

func (c *Context) TransportReturnRoute() string {
	return c.transportReturnRoute
}

func (c *Context) VDRegistry() vdrapi.Registry {
	return c.vdr
}

func (c *Context) KMS() spikms.KeyManager {
	return c.kms
}

func (c *Context) KeyAgreementType() spikms.KeyType {
	return c.keyAgreementType
}

func (c *Context) ProtocolStateStorageProvider() spistorage.Provider {
	return c.protocolStateStoreProvider
}

func (c *Context) MediaTypeProfiles() []string {
	return c.mediaTypeProfiles
}

func (c *Context) DIDRotator() *middleware.DIDCommMessageMiddleware {
	return c.didRotator
}

func (c *Context) InboundMessageHandler() transport.InboundMessageHandler {
	if c.inboundEnvelopeHandler == nil {
		c.inboundEnvelopeHandler = inbound.NewInboundMessageHandler(c)
	}

	return c.inboundEnvelopeHandler.HandlerFunc()
}

func (c *Context) Packager() transport.Packager {
	return c.packager
}

func (c *Context) AriesFrameworkID() string {
	return c.frameworkID
}

func (c *Context) Crypto() spicrypto.Crypto {
	return c.crypto
}

func (c *Context) OutboundDispatcher() dispatcher.Outbound {
	return c.outboundDispatcher
}

func (c *Context) StorageProvider() spistorage.Provider {
	return c.storeProvider
}

func (c *Context) JSONLDContextStore() ldstore.ContextStore {
	return c.contextStore
}

func (c *Context) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return c.remoteProviderStore
}

type ContextOption func(ctx *Context) error

func New(opts ...ContextOption) (*Context, error) {
	provider := Context{}

	for _, option := range opts {
		err := option(&provider)
		if err != nil {
			return nil, fmt.Errorf("option failed: %w", err)
		}
	}

	return &provider, nil
}

func WithStorageProvider(sp spistorage.Provider) ContextOption {
	return func(p *Context) error {
		p.storeProvider = sp
		return nil
	}
}

func WithKMS(k spikms.KeyManager) ContextOption {
	return func(p *Context) error {
		p.kms = k
		return nil
	}
}

func WithSecretLock(lock spisecretlock.Service) ContextOption {
	return func(ctx *Context) error {
		ctx.secretLock = lock
		return nil
	}
}

func WithCrypto(c spicrypto.Crypto) ContextOption {
	return func(p *Context) error {
		p.crypto = c
		return nil
	}
}

func WithOutboundTransports(transports ...transport.OutboundTransport) ContextOption {
	return func(opts *Context) error {
		opts.outboundTransports = transports
		return nil
	}
}

func WithPackager(packager transport.Packager) ContextOption {
	return func(opts *Context) error {
		opts.packager = packager
		return nil
	}
}

func WithProtocolStateStorageProvider(sp spistorage.Provider) ContextOption {
	return func(p *Context) error {
		p.protocolStateStoreProvider = sp
		return nil
	}
}

func WithJSONLDContextStore(store ldstore.ContextStore) ContextOption {
	return func(p *Context) error {
		p.contextStore = store
		return nil
	}
}

func WithJSONLDRemoteProviderStore(store ldstore.RemoteProviderStore) ContextOption {
	return func(p *Context) error {
		p.remoteProviderStore = store
		return nil
	}
}

func WithJSONLDDocumentLoader(loader jsonld.DocumentLoader) ContextOption {
	return func(p *Context) error {
		p.documentLoader = loader
		return nil
	}
}

func WithVDRegistry(vdr vdrapi.Registry) ContextOption {
	return func(p *Context) error {
		p.vdr = vdr
		return nil
	}
}

func WithServiceEndpoint(endpoint string) ContextOption {
	return func(p *Context) error {
		p.serviceEndpoint = endpoint
		return nil
	}
}

func WithInboundEnvelopeHandler(handler InboundEnvelopeHandler) ContextOption {
	return func(p *Context) error {
		p.inboundEnvelopeHandler = handler
		return nil
	}
}

func WithOutboundDispatcher(dispatcher dispatcher.Outbound) ContextOption {
	return func(ctx *Context) error {
		ctx.outboundDispatcher = dispatcher
		return nil
	}
}

func WithProtocolServices(services ...dispatcher.ProtocolService) ContextOption {
	return func(ctx *Context) error {
		ctx.services = services
		return nil
	}
}
