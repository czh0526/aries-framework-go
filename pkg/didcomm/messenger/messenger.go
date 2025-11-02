package messenger

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	spistorage "github.com/czh0526/aries-framework-go/spi/storage"
	"github.com/google/uuid"
)

const MessengerStore = "messenger_store"

type record struct {
	MyDID          string `json:"my_did,omitempty"`
	TheirDID       string `json:"their_did,omitempty"`
	ThreadID       string `json:"thread_id,omitempty"`
	ParentThreadID string `json:"parent_thread_id,omitempty"`
}

type Provider interface {
	OutboundDispatcher() dispatcher.Outbound
	StorageProvider() spistorage.Provider
}

type Messenger struct {
	store      spistorage.Store
	dispatcher dispatcher.Outbound
}

func (m *Messenger) HandleInbound(msg service.DIDCommMsgMap, ctx service.DIDCommContext) error {
	if msg.ID() == "" {
		return errors.New("message-id is absent and can't be processed")
	}

	thID, err := msg.ThreadID()
	if err != nil {
		return fmt.Errorf("threadID: %w", err)
	}

	return m.saveRecord(msg.ID(), record{
		MyDID:          ctx.MyDID(),
		TheirDID:       ctx.TheirDID(),
		ThreadID:       thID,
		ParentThreadID: msg.ParentThreadID(),
	})
}

func (m *Messenger) ReplyTo(msgID string, msg service.DIDCommMsgMap, opts ...service.Opt) error {
	//TODO implement me
	panic("implement me")
}

func (m *Messenger) ReplyToMsg(in, out service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
	//TODO implement me
	panic("implement me")
}

func (m *Messenger) Send(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
	fillIfMissing(msg, opts...)

	msg.UnsetThread()
	msg.SetThread(msg.ID(), "", opts...)

	return m.dispatcher.SendToDID(msg, myDID, theirDID)
}

func (m *Messenger) SendToDestination(msg service.DIDCommMsgMap, sender string,
	destination *service.Destination, opts ...service.Opt) error {
	fillIfMissing(msg, opts...)

	msg.UnsetThread()

	return m.dispatcher.Send(msg, sender, destination)
}

var logger = log.New("aries-framework/pkg/didcomm/messenger")

func NewMessenger(ctx Provider) (*Messenger, error) {
	store, err := ctx.StorageProvider().OpenStore(MessengerStore)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	return &Messenger{
		store:      store,
		dispatcher: ctx.OutboundDispatcher(),
	}, nil
}

var _ service.MessengerHandler = (*Messenger)(nil)

func (m *Messenger) saveRecord(msgID string, rec record) error {
	src, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}

	return m.store.Put(msgID, src)
}
func fillIfMissing(msg service.DIDCommMsgMap, opts ...service.Opt) {
	if msg.ID() == "" {
		msg.SetID(uuid.New().String(), opts...)
	}
}
