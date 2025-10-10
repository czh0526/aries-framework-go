package didexchange

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mediator"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
)

const (
	DIDExchange            = "didexchange"
	PIURI                  = "https://didcomm.org/didexchange/1.0"
	InvitationMsgType      = PIURI + "/invitation"
	RequestMsgType         = PIURI + "/request"
	ResponseMsgType        = PIURI + "/response"
	AckMsgType             = PIURI + "/ack"
	CompleteMsgType        = PIURI + "/complete"
	oobMsgType             = "/oob-invitation"
	routerConnsMetadataKey = "routerConnections"
)

const (
	myNSPrefix    = "my"
	theirNSPrefix = "their"
)

var logger = log.New("aries-framework/did-exchange/service")

type options struct {
	publicDID         string
	routerConnections []string
	label             string
}

type message struct {
	Msg           service.DIDCommMsgMap
	ThreadID      string
	Options       *options
	NextStateName string
	ConnRecord    *connection.Record
	err           error
}

type stateMachineMsg struct {
	service.DIDCommMsg
	connRecord *connection.Record
	options    *options
}

type provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() spistorage.Provider
	ProtocolStateStorageProvider() spistorage.Provider
	DIDConnectionStore() didstore.ConnectionStore
	Crypto() spicrypto.Crypto
	KMS() spikms.KeyManager
	VDRegistry() vdrapi.Registry
	Service(id string) (interface{}, error)
	KeyType() spikms.KeyType
	KeyAgreementType() spikms.KeyType
	MediaTypeProfiles() []string
}

type context struct {
	outboundDispatcher dispatcher.Outbound
	crypto             spicrypto.Crypto
	kms                spikms.KeyManager
	connectionRecorder *connection.Recorder
	connectionStore    didstore.ConnectionStore
	vdRegistry         vdrapi.Registry
	routeSvc           mediator.ProtocolService
	doACAPyInterop     bool
	keyType            spikms.KeyType
	keyAgreementType   spikms.KeyType
	mediaTypeProfiles  []string
}

type Service struct {
	service.Action
	service.Message
	ctx                *context
	callbackChannel    chan *message
	connectionRecorder *connection.Recorder
	connectionStore    didstore.ConnectionStore
	initialized        bool
}

func (s *Service) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	logger.Debugf("receive inbound message: %s", msg)

	thID, err := msg.ThreadID()
	if err != nil {
		return "", err
	}

	next, err := s.nextState(msg.Type(), thID)
	if err != nil {
		return "", fmt.Errorf("handle inbound - next state: %w", err)
	}

	connRecord, err := s.connectionRecord(msg)
	if err != nil {
		return "", fmt.Errorf("failed to fetch connection record: %w", err)
	}

	logger.Debugf("connection record: %s", msg)

	internalMsg := &message{
		Options:       &options{routerCibbections: retrievingRouterConnections(msg)},
		Msg:           msg.Clone(),
		ThreadID:      thID,
		NextStateName: next.Name(),
		ConnRecord:    connRecord,
	}

	go func(msg *message, aEvent chan<- service.DIDCommAction) {
		if err = s.handle(msg, aEvent); err != nil {
			logger.Errorf("processMessage failed, err = %s", err)
			return
		}

		logger.Debugf("processMessage success")

	}(internalMsg, s.ActionEvent())

	return connRecord.ConnectionID, nil
}

func (s *Service) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Service) Accept(msgType string) bool {
	return msgType == InvitationMsgType ||
		msgType == RequestMsgType ||
		msgType == ResponseMsgType ||
		msgType == AckMsgType ||
		msgType == CompleteMsgType
}

func (s *Service) Name() string {
	return DIDExchange
}

func (s *Service) Initialize(p interface{}) error {
	if s.initialized {
		return nil
	}

	prov, ok := p.(provider)
	if !ok {
		return fmt.Errorf("expected provider of type `%T`, got type `%T`", provider(nil), p)
	}

	connRecorder, err := connection.NewRecorder(prov)
	if err != nil {
		return fmt.Errorf("failed to initialize connection recorder: %w", err)
	}

	routeSvcBase, err := prov.Service(mediator.Coordination)
	if err != nil {
		return err
	}

	routeSvc, ok := routeSvcBase.(mediator.ProtocolService)
	if !ok {
		return errors.New("cast service to Route Service failed")
	}

	const callbackChannelSize = 10

	keyType := prov.KeyType()
	if keyType == "" {
		keyType = spikms.ED25519
	}

	keyAgreementType := prov.KeyAgreementType()
	if keyAgreementType == "" {
		keyAgreementType = spikms.X25519ECDHKWType
	}

	mediaTypeProfiles := prov.MediaTypeProfiles()
	if len(mediaTypeProfiles) == 0 {
		mediaTypeProfiles = []string{transport.MediaTypeAIP2RFC0019Profile}
	}

	s.ctx = &context{
		outboundDispatcher: prov.OutboundDispatcher(),
		crypto:             prov.Crypto(),
		kms:                prov.KMS(),
		vdRegistry:         prov.VDRegistry(),
		connectionRecorder: connRecorder,
		connectionStore:    prov.DIDConnectionStore(),
		routeSvc:           routeSvc,
		doACAPyInterop:     doACAPyInterop,
		keyType:            keyType,
		keyAgreementType:   keyAgreementType,
		mediaTypeProfiles:  mediaTypeProfiles,
	}

	s.callbackChannel = make(chan *message, callbackChannelSize)
	s.connectionRecorder = connRecorder
	s.connectionStore = prov.DIDConnectionStore()

	go s.startInternalListener()

	s.initialized = true
	return nil
}

func (s *Service) startInternalListener() {
	for msg := range s.callbackChannel {
		if msg.err == nil {
			msg.err = s.handleWithoutAction(msg)
		}

		if msg.err == nil {
			continue
		}

		if err := s.abandon(msg.ThreadID, msg.Msg, msg.err); err != nil {
			logger.Errorf("process callback: %s", err)
		}
	}
}

func (s *Service) handle(msg *message, aEvent chan<- service.DIDCommAction) error {
	logger.Debugf("handle message: %+v", msg)

	next, err := stateFromName(msg.NextStateName)
	if err != nil {
		return fmt.Errorf("invalid state name: %w", err)
	}

	for !isNoOp(next) {
		s.sendMsgEvents(&service.StateMsg{
			ProtocolName: DIDExchange,
			Type:         service.PreState,
			Msg:          msg.Msg.Clone(),
			StateID:      next.Name(),
			Properties:   createEventProperties(msg.ConnRecord.ConnectionID, msg.ConnRecord.InvitationID),
		})
		logger.Debugf("send pre state event %s", next.Name())

		var (
			action           stateAction
			followup         state
			connectionRecord *connection.Record
		)

		connectionRecord, followup, action, err = next.ExecuteInbound(
			&stateMachineMsg{
				DIDCommMsg: msg.Msg,
				connRecord: msg.ConnRecord,
				options:    msg.Options,
			},
			msg.ThreadID,
			s.ctx)
		if err != nil {
			return fmt.Errorf("failed to execute state '%s': %w", next.Name(), err)
		}

		connectionRecord.State = next.Name()
		logger.Debugf("finished state event %s", next.Name())

		if err = s.update(msg.Msg.Type(), connectionRecord); err != nil {
			return fmt.Errorf("failed to presist state '%s': %w", next.Name(), err)
		}

		if connectionRecord.State == StateIDCompleted {
			err = s.connectionStore.SaveDIDByResolving(connectionRecord.TheirDID, connectionRecord.RecipientKeys...)
			if err != nil {
				return fmt.Errorf("save theirDID: %w", err)
			}
		}

		if err = action(); err != nil {
			return fmt.E
		}
	}

	return nil
}

func (s *Service) sendMsgEvents(msg *service.StateMsg) {
	for _, handler := range s.MsgEvents() {
		handler <- *msg
	}
}

func isNoOp(s state) bool {
	_, ok := s.(*noOp)
	return ok
}

var _ dispatcher.ProtocolService = (*Service)(nil)
