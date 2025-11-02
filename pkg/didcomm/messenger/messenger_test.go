package messenger

import (
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/decorator"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
	"testing"

	dispatcherMocks "github.com/czh0526/aries-framework-go/pkg/internal/gomocks/didcomm/dispatcher"
	messengerMocks "github.com/czh0526/aries-framework-go/pkg/internal/gomocks/didcomm/messenger"
	storageMocks "github.com/czh0526/aries-framework-go/pkg/internal/gomocks/spi/storage"
)

const (
	ID       = "ID"
	myDID    = "myDID"
	theirDID = "theirDID"
	msgID    = "msgID"
	errMsg   = "test error"

	jsonID             = "@id"
	jsonThread         = "~thread"
	jsonThreadID       = "thid"
	jsonParentThreadID = "pthid"
)

var _ service.MessengerHandler = (*Messenger)(nil)

func TestNewMessenger(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)
	})

	t.Run("open store error", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(
			nil, errors.New("test error"))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)

		msgr, err := NewMessenger(provider)
		require.Error(t, err)
		require.Nil(t, msgr)
	})
}

func TestMessenger_HandleInbound(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("success", func(t *testing.T) {
		store := storageMocks.NewMockStore(ctrl)
		store.EXPECT().Put(ID, gomock.Any()).Return(nil)

		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(store, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.HandleInbound(
			service.DIDCommMsgMap{jsonID: ID},
			service.NewDIDCommContext(myDID, theirDID, nil))
		require.NoError(t, err)
	})

	t.Run("absent ID", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(nil)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.HandleInbound(
			service.DIDCommMsgMap{},
			service.NewDIDCommContext(myDID, theirDID, nil))
		require.Contains(t, fmt.Sprintf("%v", err), "message-id is absent")
	})
}

func TestMessenger_Send(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("send success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().SendToDID(gomock.Any(), myDID, theirDID).
			Do(sendToDIDCheck(t, jsonID))

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.Send(service.DIDCommMsgMap{jsonID: ID}, myDID, theirDID)
		require.NoError(t, err)
	})

	t.Run("send to destination success", func(t *testing.T) {
		storageProvider := storageMocks.NewMockProvider(ctrl)
		storageProvider.EXPECT().OpenStore(gomock.Any()).Return(nil, nil)

		outbound := dispatcherMocks.NewMockOutbound(ctrl)
		outbound.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

		provider := messengerMocks.NewMockProvider(ctrl)
		provider.EXPECT().StorageProvider().Return(storageProvider)
		provider.EXPECT().OutboundDispatcher().Return(outbound)

		msgr, err := NewMessenger(provider)
		require.NoError(t, err)
		require.NotNil(t, msgr)

		err = msgr.SendToDestination(service.DIDCommMsgMap{jsonID: ID}, "", &service.Destination{})
		require.NoError(t, err)
	})
}

func sendToDIDCheck(t *testing.T, checks ...string) func(msg service.DIDCommMsgMap, msDID, theirDID string) error {
	return func(msg service.DIDCommMsgMap, msDID, theirDID string) error {
		v := struct {
			ID     string           `json:"@id"`
			Thread decorator.Thread `json:"~thread"`
		}{}

		require.NoError(t, msg.Decode(&v))

		for _, check := range checks {
			switch check {
			case jsonID:
				require.NotEmpty(t, v.ID)
			case jsonThreadID:
				require.NotEmpty(t, v.Thread.ID)
			case jsonParentThreadID:
				require.NotEmpty(t, v.Thread.PID)
			}
		}

		return nil
	}
}
