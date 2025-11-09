package api

import (
	"errors"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/store/did"
	"github.com/czh0526/aries-framework-go/pkg/store/verifiable"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spisecretlock "github.com/czh0526/aries-framework-go/spi/secretlock"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

var ErrSvcNotFound = errors.New("service not found")

type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	InboundDIDCommMessageHandler() func() service.InboundHandler
	Messenger() service.Messenger
	Service(id string) (interface{}, error)
	StorageProvider() spistorage.Provider
	KMS() spikms.KeyManager
	SecretLock() spisecretlock.Service
	Crypto() spicrypto.Crypto
	Packager() transport.Packager
	ServiceEndpoint() string
	RouterEndpoint() string
	VDRegistry() vdrapi.Registry
	ProtocolStateStorageProvider() spistorage.Provider
	InboundMessageHandler() transport.InboundMessageHandler
	VerifiableStore() verifiable.Store
	DIDConnectionStore() did.ConnectionStore
	KeyType() spikms.KeyType
	KeyAgreementType() spikms.KeyType
	MediaTypeProfiles() []string
	AriesFrameworkID() string
	ServiceMsgTypeTargets() []dispatcher.MessageTypeTarget
}

type ProtocolSvcCreator struct {
	Create         func(prov Provider) (dispatcher.ProtocolService, error)
	Init           func(svc dispatcher.ProtocolService, prov Provider) error
	ServicePointer dispatcher.ProtocolService
}

type MessageServiceProvider interface {
	Services() []dispatcher.MessageService
}
