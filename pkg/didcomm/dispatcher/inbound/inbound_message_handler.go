package inbound

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/cenkalti/backoff/v4"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/czh0526/aries-framework-go/component/log"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/middleware"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/didexchange"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/legacyconnection"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	"github.com/czh0526/aries-framework-go/pkg/doc/did"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries/api"
	didstore "github.com/czh0526/aries-framework-go/pkg/store/did"
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	"strings"
	"time"
)

var logger = log.New("dispatcher/inbound")

const (
	kaIdentifier = "#"
)

type MessageHandler struct {
	didConnectionStore     didstore.ConnectionStore
	didcommV2Handler       *middleware.DIDCommMessageMiddleware
	msgSvcProvider         api.MessageServiceProvider
	services               []dispatcher.ProtocolService
	getDIDsBackOffDuration time.Duration
	getDIDsMaxRetries      uint64
	messenger              service.InboundMessenger
	vdr                    vdrapi.Registry
	initialized            bool
}

func (mh *MessageHandler) HandleInboundEnvelope(envelope *transport.Envelope) error {
	var (
		msg service.DIDCommMsgMap
		err error
	)

	msg, err = service.ParseDIDCommMsgMap(envelope.Message)
	if err != nil {
		return err
	}

	isDIDEx := (&didexchange.Service{}).Accept(msg.Type())
	isLegacyConn := (&legacyconnection.Service{}).Accept(msg.Type())

	isV2, err := service.IsDIDCommV2(&msg)
	if err != nil {
		return err
	}

	var (
		myDID, theirDID string
		gotDIDs         bool
	)

	err = mh.didcommV2Handler.HandleInboundPeerDID(msg)
	if err != nil {
		return fmt.Errorf("handling inbound peer DID: %w", err)
	}

	if !isDIDEx && !isLegacyConn {
		myDID, theirDID, err = mh.getDIDs(envelope, msg)
		if err != nil {
			return fmt.Errorf("get DIDs for message: %w", err)
		}

		gotDIDs = true

		err = mh.didcommV2Handler.HandleInboundMessage(msg, theirDID, myDID)
		if err != nil {
			return fmt.Errorf("handling rotation: %w", err)
		}
	}

	var foundService dispatcher.ProtocolService

	for _, svc := range mh.services {
		if svc.Accept(msg.Type()) {
			foundService = svc
			break
		}
	}

	if foundService != nil {
		props := make(map[string]interface{})

		switch foundService.Name() {
		case didexchange.DIDExchange:
		case legacyconnection.LegacyConnection:
			if msg.Type() == legacyconnection.RequestMsgType && msg.ParentThreadID() == "" {
				props[legacyconnection.InvitationRecipientKey] = base58.Encode(envelope.ToKey)
			}
		default:
			if !gotDIDs {
				myDID, theirDID, err = mh.getDIDs(envelope, msg)
				if err != nil {
					return fmt.Errorf("inbound message handler: %w", err)
				}
			}
		}

		_, err = foundService.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, props))
		return err
	}

	if !isV2 {
		h := struct {
			Purpose []string `json:"~purpose"`
		}{}
		err = msg.Decode(&h)

		if err != nil {
			return err
		}

		var foundMessageService dispatcher.MessageService

		for _, svc := range mh.msgSvcProvider.Services() {
			if svc.Accept(msg.Type(), h.Purpose) {
				foundMessageService = svc
			}
		}

		if foundMessageService != nil {
			if !gotDIDs {
				myDID, theirDID, err = mh.getDIDs(envelope, msg)
				if err != nil {
					return fmt.Errorf("inbound message handler: %w", err)
				}
			}

			return mh.tryToHandle(foundMessageService, msg, service.NewDIDCommContext(myDID, theirDID, nil))
		}
	}

	return fmt.Errorf("no message handlers found for the message type: %s", msg.Type())
}

func (mh *MessageHandler) HandlerFunc() transport.InboundMessageHandler {
	return func(envelope *transport.Envelope) error {
		return mh.HandleInboundEnvelope(envelope)
	}
}

func (mh *MessageHandler) tryToHandle(
	svc service.InboundHandler, msg service.DIDCommMsgMap, ctx service.DIDCommContext) error {
	if err := mh.messenger.HandleInbound(msg, ctx); err != nil {
		return fmt.Errorf("messenger HandleInbound: %w", err)
	}

	_, err := svc.HandleInbound(msg, ctx)

	return err
}

func (mh *MessageHandler) getDIDs(
	envelope *transport.Envelope, message service.DIDCommMsgMap) (string, string, error) {
	var (
		myDID    string
		theirDID string
		err      error
	)

	myDID, err = mh.getDIDGivenKey(envelope.ToKey)
	if err != nil {
		return myDID, theirDID, err
	}

	theirDID, err = mh.getDIDGivenKey(envelope.FromKey)
	if err != nil {
		return myDID, theirDID, err
	}

	if len(envelope.FromKey) == 0 && message != nil && theirDID == "" {
		if from, ok := message["from"].(string); ok {
			didURL, e := did.ParseDIDURL(from)
			if e == nil {
				theirDID = didURL.DID.String()
			}
		}
	}

	return myDID, theirDID, backoff.Retry(func() error {
		var notFound bool

		if myDID == "" {
			myDID, err = mh.didConnectionStore.GetDID(base58.Encode(envelope.ToKey))
			if errors.Is(err, didstore.ErrNotFound) {
				didKey, _ := fingerprint.CreateDIDKey(envelope.ToKey)
				myDID, err = mh.didConnectionStore.GetDID(didKey)
			}

			if errors.Is(err, didstore.ErrNotFound) {
				notFound = true
			} else if err != nil {
				myDID = ""
				return fmt.Errorf("failed to get my did: %w", err)
			}
		}

		if envelope.FromKey == nil {
			return nil
		}

		if theirDID == "" {
			theirDID, err = mh.didConnectionStore.GetDID(base58.Encode(envelope.FromKey))
			if errors.Is(err, didstore.ErrNotFound) {
				didKey, _ := fingerprint.CreateDIDKey(envelope.FromKey)
				theirDID, err = mh.didConnectionStore.GetDID(didKey)
			}

			if err == nil {
				return nil
			}

			if notFound && errors.Is(err, didstore.ErrNotFound) {
				return nil
			}

			theirDID = ""
			return fmt.Errorf("failed to get their did: %w", err)
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(mh.getDIDsBackOffDuration), mh.getDIDsMaxRetries))
}

func (mh *MessageHandler) getDIDGivenKey(key []byte) (string, error) {
	var (
		err    error
		retDID string
	)

	if strings.Index(string(key), kaIdentifier) > 0 &&
		strings.Index(string(key), "\"kid\":\"did:") > 0 {
		retDID, err = pubKeyToDID(key)
		if err != nil {
			return "", fmt.Errorf("getDID: %w", err)
		}

		logger.Debugf("envelope Key as DID: %v", retDID)
		return retDID, nil
	}

	return "", nil
}

func pubKeyToDID(kwy []byte) (string, error) {
	toKey := &spicrypto.PublicKey{}

	err := json.Unmarshal(kwy, toKey)
	if err != nil {
		return "", fmt.Errorf("pubKeyToDID: unmarshal key: %w", err)
	}

	return toKey.KID[:strings.Index(toKey.KID, kaIdentifier)], nil
}

func (mh *MessageHandler) Initialize(p provider) {
	return
}

type provider interface {
}

func NewInboundMessageHandler(p provider) *MessageHandler {
	h := MessageHandler{}
	h.Initialize(p)

	return &h
}
