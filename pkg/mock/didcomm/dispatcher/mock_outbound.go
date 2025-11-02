package dispatcher

import "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

type MockOutbound struct {
	ValidateSend      func(msg interface{}, senderVerKey string, des *service.Destination) error
	ValidateSendToDID func(msg interface{}, myDID, theirDID string) error
	ValidateForward   func(msg interface{}, des *service.Destination) error
	SendErr           error
}

func (m *MockOutbound) Send(msg interface{}, senderVerKey string, des *service.Destination) error {
	if m.ValidateSend != nil {
		return m.ValidateSend(msg, senderVerKey, des)
	}

	return m.SendErr
}

func (m *MockOutbound) SendToDID(msg interface{}, myDID, theirDID string) error {
	if m.ValidateSendToDID != nil {
		return m.ValidateSendToDID(msg, myDID, theirDID)
	}
	return m.SendErr
}

func (m *MockOutbound) Forward(msg interface{}, des *service.Destination) error {
	if m.ValidateForward != nil {
		return m.ValidateForward(msg, des)
	}

	return nil
}
