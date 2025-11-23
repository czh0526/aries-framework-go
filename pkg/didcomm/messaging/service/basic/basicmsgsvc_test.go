package basic

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMessageService_HandleInbound(t *testing.T) {
	const myDID = "sample-my-did"
	const theirDID = "sample-their-did"

	t.Run("test MessageService.HandleInbound()", func(t *testing.T) {
		const jsonStr = `{
			"@id": "123456780",
			"@type": "https://didcomm.org/basicmessage/1.0/message",
			"~i10n": {"locale": "en"},
			"content": "Your hovercragt is full of eels."
		}`

		testCh := make(chan struct {
			message  Message
			myDID    string
			theirDID string
		})

		handleFn := func(message Message, ctx service.DIDCommContext) error {
			testCh <- struct {
				message  Message
				myDID    string
				theirDID string
			}{
				message:  message,
				myDID:    ctx.MyDID(),
				theirDID: ctx.TheirDID(),
			}
			return nil
		}

		svc, err := NewMessageService("sample-name", handleFn)
		require.NoError(t, err)
		require.NotNil(t, svc)

		go func() {
			msg, err := service.ParseDIDCommMsgMap([]byte(jsonStr))
			require.NoError(t, err)

			_, err = svc.HandleInbound(msg, service.NewDIDCommContext(myDID, theirDID, nil))
			require.NoError(t, err)
		}()

		select {
		case x := <-testCh:
			require.NotNil(t, x)
			require.Equal(t, x.myDID, myDID)
			require.Equal(t, x.theirDID, theirDID)
			require.Equal(t, x.message.I10n.Locale, "en")
			require.Equal(t, x.message.Content, "Your hovercraft is full of eels.")
			require.Equal(t, x.message.ID, "123456780")

		case <-time.After(2 * time.Second):
			require.Fail(t, "timed out, didn't receive basic message to handle")
		}
	})

	t.Run("test MessageService.HandleInbound() error", func(t *testing.T) {
		const sampleErr = "sample-error"
		svc, err := NewMessageService("sample-name", getMockMessageHandle())
		require.NoError(t, err)
		require.NotNil(t, svc)

		_, err = svc.HandleInbound(&mockMsg{
			err: fmt.Errorf(sampleErr),
		}, service.NewDIDCommContext(myDID, theirDID, nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), sampleErr)
	})

}

func getMockMessageHandle() MessageHandle {
	return func(Message, service.DIDCommContext) error {
		return nil
	}
}

type mockMsg struct {
	*service.DIDCommMsgMap
	err error
}

func (m *mockMsg) Decode(v interface{}) error {
	return m.err
}
