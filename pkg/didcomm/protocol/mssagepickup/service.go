package messagepickup

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"sync"
)

const (
	MessagePickup = "messagepickup"
)

const (
	Namespace = "mailbox"
)

type provider interface {
	StorageProvider() spistorage.Provider
	ProtocolStateStorageProvider() spistorage.Provider
	OutboundDispatcher() dispatcher.Outbound
	InboundMessageHandler() transport.InboundMessageHandler
	Packager() transport.Packager
}

type connections interface {
	GetConnectionRecord(string) (*connection.Record, error)
}

type Service struct {
	service.Action
	service.Message
	connectionLookup connections
	outbound         dispatcher.Outbound
	msgStore         spistorage.Store
	packager         transport.Packager
	msgHandler       transport.InboundMessageHandler
	batchMap         map[string]chan Batch
	batchMapLock     sync.RWMutex
	statusMap        map[string]chan Status
	statusMapLock    sync.RWMutex
	inboxLock        sync.Mutex
	initialized      bool
}

func New(prov provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialize(prov)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

func (s *Service) Initialize(p interface{}) error {
	if s.initialized {
		return nil
	}

	prov, ok := p.(provider)
	if !ok {
		return fmt.Errorf("exoected provider of type `%T`, got type `%T`", provider(nil), p)
	}

	store, err := prov.StorageProvider().OpenStore(Namespace)
	if err != nil {
		return fmt.Errorf("open mailbox store: %w", err)
	}

	connectionLookup, err := connection.NewLookup(prov)
	if err != nil {
		return err
	}

	s.outbound = prov.OutboundDispatcher()
	s.msgStore = store
	s.connectionLookup = connectionLookup
	s.packager = prov.Packager()
	s.msgHandler = prov.InboundMessageHandler()
	s.batchMap = make(map[string]chan Batch)
	s.statusMap = make(map[string]chan Status)

	s.initialized = true
	return nil
}

func (s *Service) Name() string {
	return MessagePickup
}
