package mediator

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	msgpickupprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	connstore "github.com/czh0526/aries-framework-go/pkg/store/connection"
	medprotocol "github.com/czh0526/aries-framework-go/provider/didcomm/protocol/mediator"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"sync"
	"time"
)

var logger = log.New("aries-framework//route/service")

const (
	Coordination = "coordinatemediation"
)

const (
	routeConnIDDataKey = "route_connID_%s"
	routeConfigDataKey = "route_config_%s"
	routeGrantKey      = "grant_%s"
)

var (
	ErrConnectionNotFound  = errors.New("connstore not found")
	ErrRouterNotRegistered = errors.New("router not registered")
)

type ClientOptions struct {
	Timeout time.Duration
}

type ClientOption func(opts *ClientOptions)

type Options struct {
	ServiceEndpoint string
	RoutingKeys     []string
}

type callback struct {
	msg      service.DIDCommMsg
	myDID    string
	theirDID string
	options  *Options
	err      error
}

type connections interface {
	GetConnectionIDByDIDs(string, string) (string, error)
	GetConnectionRecord(string) (*connstore.Record, error)
	GetConnectionRecordByDIDs(myDID string, theirDID string) (*connstore.Record, error)
}

type Service struct {
	service.Action
	service.Message
	routeStore           spistorage.Store
	connectionLookup     connections
	outbound             dispatcher.Outbound
	endpoint             string
	kms                  spikms.KeyManager
	vdRegistry           vdrapi.Registry
	keylistUpdateMap     map[string]chan *KeylistUpdateResponse
	keylistUpdateMapLock sync.RWMutex
	callbacks            chan *callback
	messagePickupSvc     msgpickupprotocol.ProtocolService
	keyAgreementType     spikms.KeyType
	mediaTypeProfiles    []string
	initialized          bool
	debugDisableBackoff  bool
}

func New(p medprotocol.Provider) (*Service, error) {
	svc := Service{}

	err := svc.Initialized(p)
	if err != nil {
		return nil, err
	}

	return &svc, nil
}

func (s *Service) Initialized(p interface{}) error {
	if s.initialized {
		return nil
	}

	prov, ok := p.(medprotocol.Provider)
	if !ok {
		return fmt.Errorf("expected provider of type `%T`, got type `%T`",
			medprotocol.Provider(nil), p)
	}

	store, err := prov.StorageProvider().OpenStore(Coordination)
	if err != nil {
		return fmt.Errorf("open route coordination store failed: %w", err)
	}

	err = prov.StorageProvider().SetStoreConfig(Coordination,
		spistorage.StoreConfiguration{TagNames: []string{routeConnIDDataKey}})
	if err != nil {
		return fmt.Errorf("failed to set route coordination store configuration: %w", err)
	}

	connectionLookup, err := connstore.NewLookup(prov)
	if err != nil {
		return err
	}

	mp, err := prov.Service(msgpickupprotocol.MessagePickup)
	if err != nil {
		return err
	}

	messagePickupSvc, ok := mp.(msgpickupprotocol.ProtocolService)
	if !ok {
		return errors.New("cast service to message pickup service failed")
	}

	s.routeStore = store
	s.outbound = prov.OutboundDispatcher()
	s.endpoint = prov.RouterEndpoint()
	s.kms = prov.KMS()
	s.vdRegistry = prov.VDRegistry()
	s.connectionLookup = connectionLookup
	s.keylistUpdateMap = make(map[string]chan *KeylistUpdateResponse)
	s.callbacks = make(chan *callback)
	s.messagePickupSvc = messagePickupSvc
	s.keyAgreementType = prov.KeyAgreementType()
	s.mediaTypeProfiles = prov.MediaTypeProfiles()

	logger.Debugf("default endpoint: %s", s.endpoint)

	go s.listenForCallbacks()

	s.initialized = true
	return nil
}

func (s *Service) sendActionEvent(msg service.DIDCommMsg, myDID, theirDID string) error {
	events := s.ActionEvent()
	if events == nil {
		return fmt.Errorf("no clients registered to handle action events for `%s` protocol", Coordination)
	}

	logger.Debugf("dispatching action event for msg=%+v, myDID=%s, theirDID=%s", msg, myDID, theirDID)

	go func() {
		c := &callback{
			msg:      msg,
			myDID:    myDID,
			theirDID: theirDID,
		}

		// 构建一个 ActionEvent，并投递到事件通道
		events <- service.DIDCommAction{
			ProtocolName: Coordination,
			Message:      msg,
			Continue: func(args interface{}) {
				switch o := args.(type) {
				case Options:
					c.options = &o
				case *Options:
					c.options = &Options{}
				}

				s.callbacks <- c
			},
			Stop: func(err error) {
				c.err = err
				s.callbacks <- c
			},
		}
	}()

	return nil
}

type getConnectionOpts struct {
	version service.Version
}

type ConnectionOption func(opts *getConnectionOpts)

func ConnectionByVersion(v service.Version) ConnectionOption {
	return func(opts *getConnectionOpts) {
		opts.version = v
	}
}
