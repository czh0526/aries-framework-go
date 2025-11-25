package mediator

import (
	"errors"
	"github.com/czh0526/aries-framework-go/component/log"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	messagepickup "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mssagepickup"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"sync"
	"time"
)

var logger = log.New("aries-framework//route/service")

const (
	Coordination = "coordinatemediation"
)

var (
	ErrConnectionNotFound  = errors.New("connection not found")
	ErrRouterNotRegistered = errors.New("router not registered")
)

type ClientOptions struct {
	Timeout time.Duration
}

type ClientOption func(opts ClientOptions)

type Options struct {
	ServiceEndpoint string
	RoutingKeys     []string
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

type connections interface {
	GetConnectionIDByDIDs(string, string) (string, error)
	GetConnectionRecord(string) (*connection.Record, error)
	GetConnectionRecordByDIDs(myDID string, theirDID string) (*connection.Record, error)
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
	//callbacks            chan *callback
	messagePickupSvc    messagepickup.ProtocolService
	keyAgreementType    spikms.KeyType
	mediaTypeProfiles   []string
	initialized         bool
	debugDisableBackoff bool
}
