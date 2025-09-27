package outbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	"github.com/czh0526/aries-framework-go/component/log"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	commonmodel "github.com/czh0526/aries-framework-go/pkg/common/model"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/model"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/store/connection"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/google/uuid"
	"strings"
)

type provider interface {
	Packager() transport.Packager
	OutboundTransports() []transport.OutboundTransport
	TransportReturnRoute() string
	VDRegistry() vdrapi.Registry
	KMS() spikms.KeyManager
	KeyAgreementType() spikms.KeyType
	ProtocolStateStorageProvider() spistorage.Provider
	StorageProvider() spistorage.Provider
	MediaTypeProfiles() []string
	DIDRotator() *middleware.DIDCommMessageMiddleware
}

type connectionLookup interface {
	GetConnectionIDByDIDs(myDID, theirDID string) (string, error)
	GetConnectionRecord(string) (*connection.Record, error)
	GetConnectionRecordByDIDs(myDID, theirDID string) (*connection.Record, error)
}

type connectionRecorder interface {
	connectionLookup
	SaveConnectionRecord(*connection.Record) error
}

type Dispatcher struct {
	outboundTransports   []transport.OutboundTransport
	packager             transport.Packager
	transportReturnRoute string
	vdRegistry           vdrapi.Registry
	kms                  spikms.KeyManager
	keyAgreementType     spikms.KeyType
	connections          connectionRecorder
	mediaTypeProfiles    []string
	didcommV2Handler     *middleware.DIDCommMessageMiddleware
}

func (o *Dispatcher) SendToDID(msg interface{}, myDID, theirDID string) error {
	myDocResolution, err := o.vdRegistry.Resolve(myDID)
	if err != nil {
		return fmt.Errorf("failed to resolve myDID %q: %w", myDID, err)
	}

	theirDocResolution, err := o.vdRegistry.Resolve(theirDID)
	if err != nil {
		return fmt.Errorf("failed to resolve theirDID %q: %w", theirDID, err)
	}

	var connectionVersion service.Version
	didcommMsg, isMsgMap := msg.(service.DIDCommMsgMap)

	var isV2 bool

	if isMsgMap {
		isV2, err = service.IsDIDCommV2(&didcommMsg)
		if err == nil && isV2 {
			connectionVersion = service.V2
		} else {
			connectionVersion = service.V1
		}
	}

	connRec, err := o.getOrCreateConnection(myDID, theirDID, connectionVersion)
	if err != nil {
		return fmt.Errorf("failed to fetch connection record: %w", err)
	}

	var sendWithAnoncrypt bool

	if isMsgMap {
		didcommMsg = o.didcommV2Handler.HandleOutboundMessage(didcommMsg, connRec)

		if connRec.PeerDIDInitialState != "" {
			sendWithAnoncrypt = true
		}

		if connRec.DIDCommVersion == service.V2 && connRec.ParentThreadID != "" && connectionVersion == service.V2 {
			pthid, hasPthid := didcommMsg["pthid"].(string)
			thid, e := didcommMsg.ThreadID()
		}
		msg = &didcommMsg
	} else {

	}
}

func (o *Dispatcher) Forward(i interface{}, destination *service.Destination) error {
	//TODO implement me
	panic("implement me")
}

func (o *Dispatcher) getOrCreateConnection(myDID, theirDID string, connectionVersion service.Version) (
	*connection.Record, error) {

	record, err := o.connections.GetConnectionRecordByDIDs(myDID, theirDID)
	if err == nil {
		return record, nil
	} else if !errors.Is(err, spistorage.ErrDataNotFound) {
		return nil, fmt.Errorf("failed to check if connection exists: %w", err)
	}

	logger.Debugf("no connection record found for myDID=%s theirDID=%s, will create", myDID, theirDID)

	newRecord := connection.Record{
		ConnectionID:   uuid.New().String(),
		MyDID:          myDID,
		TheirDID:       theirDID,
		State:          connection.StateNameCompleted,
		Namespace:      connection.MyNSPrefix,
		DIDCommVersion: connectionVersion,
	}

	if connectionVersion == service.V2 {
		newRecord.ServiceEndPoint = commonmodel.NewDIDCommV2Endpoint()
	} else {
		newRecord.MediaTypeProfiles = o.defaultMediaTypeProfiles()
	}

	err = o.connections.SaveConnectionRecord(&newRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to save connection record: %w", err)
	}

	return &newRecord, nil
}

var _ dispatcher.Outbound = (*Dispatcher)(nil)

type legacyForward struct {
	Type string          `json:"@type,omitempty"`
	ID   string          `json:"@id,omitempty"`
	To   string          `json:"to,omitempty"`
	Msg  *model.Envelope `json:"msg,omitempty"`
}

var logger = log.New("aries-framework/didcomm/dispatcher")

func NewOutbound(prov provider) (*Dispatcher, error) {
	o := &Dispatcher{
		outboundTransports:   prov.OutboundTransports(),
		packager:             prov.Packager(),
		transportReturnRoute: prov.TransportReturnRoute(),
		vdRegistry:           prov.VDRegistry(),
		kms:                  prov.KMS(),
		keyAgreementType:     prov.KeyAgreementType(),
		mediaTypeProfiles:    prov.MediaTypeProfiles(),
		didcommV2Handler:     prov.DIDRotator(),
	}

	var err error
	o.connections, err = connection.NewRecorder(prov)
	if err != nil {
		return nil, fmt.Errorf("failed to init connection recorder: %w", err)
	}

	return o, nil
}

func (o *Dispatcher) Send(msg interface{}, senderKey string, dest *service.Destination) error {
	keys := dest.RecipientKeys
	if routingKeys, err := dest.ServiceEndpoint.RoutingKeys(); err == nil && len(routingKeys) > 0 {
		keys = routingKeys
	} else if len(dest.RoutingKeys) > 0 {
		keys = routingKeys
	}

	var outboundTransport transport.OutboundTransport
	for _, v := range o.outboundTransports {
		uri, err := dest.ServiceEndpoint.URI()
		if err != nil {
			logger.Debugf("destination ServiceEndpoint empty: %w, it will not be checked", err)
		}

		if v.AcceptRecipient(keys) || v.Accept(uri) {
			outboundTransport = v
			break
		}
	}

	if outboundTransport == nil {
		return fmt.Errorf("outboundDispatcher.Send: no transport found for dstination: %+v", dest)
	}

	req, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.Send: failed marshal to bytes: %w", err)
	}

	req, err = o.addTransportRouteOptions(req, dest)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.Send: failed to addTransportRouteOptions: %w", err)
	}

	mtp := o.mediaTypeProfile(dest)

	var fromKey []byte

	if len(senderKey) > 0 {
		fromKey = []byte(senderKey)
	}

	packedMsg, err := o.packager.PackMessage(&transport.Envelope{
		MediaTypeProfile: mtp,
		Message:          req,
		FromKey:          fromKey,
		ToKeys:           dest.RecipientKeys,
	})
	if err != nil {
		return fmt.Errorf("outboundDispatcher.Send: failed to pack message: %w", err)
	}

	dest.TransportReturnRoute = o.transportReturnRoute

	packedMsg, err = o.createForwardMessage(packedMsg, dest)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.Send: failed to createForwardMessage: %w", err)
	}

	_, err = outboundTransport.Send(packedMsg, dest)
	if err != nil {
		return fmt.Errorf("outboundDispatcher.Send: failed to send msg using outbound transport: %w", err)
	}

	return nil
}

func (o *Dispatcher) addTransportRouteOptions(req []byte, dest *service.Destination) ([]byte, error) {
	if routingKeys, err := dest.ServiceEndpoint.RoutingKeys(); err == nil && len(routingKeys) > 0 {
		return req, nil
	}

	if o.transportReturnRoute == decorator.TransportReturnRouteAll ||
		o.transportReturnRoute == decorator.TransportReturnRouteThread {
		transportDec := &decorator.Transport{
			ReturnRoute: &decorator.ReturnRoute{
				Value: o.transportReturnRoute,
			},
		}

		transportDecJSON, jsonErr := json.Marshal(transportDec)
		if jsonErr != nil {
			return nil, fmt.Errorf("json marshal: %w", jsonErr)
		}

		request := string(req)
		index := strings.Index(request, "{")

		req = []byte(request[:index+1] + string(transportDecJSON)[1:len(string(transportDecJSON))-1] + "," +
			request[index+1:])
	}

	return req, nil
}

func (o *Dispatcher) createForwardMessage(msg []byte, dest *service.Destination) ([]byte, error) {
	mtProfile := o.mediaTypeProfile(dest)

	var (
		forwardMsgType string
		err            error
	)

	switch mtProfile {
	case transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2EncryptedEnvelope,
		transport.MediaTypeAIP2RFC0587Profile, transport.MediaTypeV2PlaintextPayload, transport.MediaTypeDIDCommV2Profile:
		forwardMsgType = service.ForwardMsgTypeV2
	default:
		forwardMsgType = service.ForwardMsgType
	}

	routingKeys, err := dest.ServiceEndpoint.RoutingKeys()
	if err != nil {
		logger.Debugf("dest.ServiceEndpoint.RoutingKeys() (didcomm v2) returned an error %w, "+
			"will check routinKeys (didcomm v1) array", err)
	}

	if len(routingKeys) == 0 {
		if len(dest.RoutingKeys) == 0 {
			return msg, nil
		}

		routingKeys = dest.RoutingKeys
	}

	fwdKeys := append([]string{dest.RecipientKeys[0]}, routingKeys...)

	packedMsg, err := o.createPackedNestedForwards(msg, fwdKeys, forwardMsgType, mtProfile)
	if err != nil {
		return nil, fmt.Errorf("failed to creat packed nested forwards: %w", err)
	}

	return packedMsg, nil
}

func (o *Dispatcher) createPackedNestedForwards(msg []byte, routingKeys []string, fwdMsgType, mtProfile string) (
	[]byte, error) {

	for i, key := range routingKeys {
		if i+1 >= len(routingKeys) {
			break
		}

		forward := model.Forward{
			Type: fwdMsgType,
			ID:   uuid.New().String(),
			To:   key,
			Msg:  msg,
		}

		var err error

		msg, err = o.packForward(forward, []string{routingKeys[i+1]}, mtProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to pack forward msg: %w", err)
		}
	}

	return msg, nil
}

func (o *Dispatcher) packForward(fwd model.Forward, toKeys []string, mtProfile string) ([]byte, error) {
	env := &model.Envelope{}

	var (
		forward interface{}
		err     error
		req     []byte
	)

	err = json.Unmarshal(fwd.Msg, env)
	if err == nil {
		if strings.HasPrefix(fwd.To, "did:key") && mtProfile == transport.LegacyDIDCommV1Profile {
			fwd.To, err = kmsdidkey.GetBase58PubKeyFromDIDKey(fwd.To)
			if err != nil {
				return nil, err
			}
		}

		forward = legacyForward{
			Type: fwd.Type,
			ID:   fwd.ID,
			To:   fwd.To,
			Msg:  env,
		}
	} else {
		forward = fwd
	}

	req, err = json.Marshal(forward)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to bytes: %w", err)
	}

	var packedMsg []byte
	packedMsg, err = o.packager.PackMessage(&transport.Envelope{
		MediaTypeProfile: mtProfile,
		Message:          req,
		FromKey:          []byte{},
		ToKeys:           toKeys,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to pack forward msg: %w", err)
	}

	return packedMsg, nil
}

func (o *Dispatcher) mediaTypeProfile(dest *service.Destination) string {
	var (
		mt     string
		accept []string
		err    error
	)

	if accept, err = dest.ServiceEndpoint.Accept(); err != nil || len(accept) == 0 {
		accept = dest.MediaTypeProfiles
	}

	if len(accept) > 0 {
		for _, mtp := range accept {
			switch mtp {
			case transport.MediaTypeV1PlaintextPayload, transport.MediaTypeRFC0019EncryptedEnvelope,
				transport.MediaTypeAIP2RFC0019Profile, transport.MediaTypeProfileDIDCommAIP1,
				transport.LegacyDIDCommV1Profile:
				// 最低优先级，如果没有取得值，先临时暂存
				if mt == "" {
					mt = mtp
				}
			case transport.MediaTypeV1EncryptedEnvelope, transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
				transport.MediaTypeAIP2RFC0587Profile:
				// 第二高优先级，覆盖之前的暂存的值
				mt = mtp
			case transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2PlaintextPayload,
				transport.MediaTypeDIDCommV2Profile:
				// V2 是最高优先级，直接返回
				return mtp
			}
		}
	}

	if mt == "" {
		return o.defaultMediaTypeProfiles()[0]
	}

	return mt
}

func (o *Dispatcher) defaultMediaTypeProfiles() []string {
	mediaTypes := make([]string, len(o.mediaTypeProfiles))
	copy(mediaTypes, o.mediaTypeProfiles)
	return mediaTypes
}
