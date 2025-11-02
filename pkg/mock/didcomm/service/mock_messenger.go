package service

import "github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"

type MockMessenger struct {
	ErrReplyTo           error
	ReplyToMsgFunc       func(service.DIDCommMsgMap, service.DIDCommMsgMap, string, string) error
	ErrReplyToNested     error
	ErrSend              error
	ErrSendToDestination error
}

func (m *MockMessenger) ReplyTo(msgID string, msg service.DIDCommMsgMap, opts ...service.Opt) error {
	if m.ErrReplyTo != nil {
		return m.ErrReplyTo
	}

	return nil
}

func (m *MockMessenger) ReplyToMsg(in, out service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
	if m.ReplyToMsgFunc != nil {
		return m.ReplyToMsgFunc(in, out, myDID, theirDID)
	}
	return nil
}

func (m *MockMessenger) Send(msg service.DIDCommMsgMap, myDID, theirDID string, opts ...service.Opt) error {
	if m.ErrSend != nil {
		return m.ErrSend
	}

	return nil
}

// ReplyToNested mock messenger reply to nested.
func (m *MockMessenger) ReplyToNested(msg service.DIDCommMsgMap, opts *service.NestedReplyOpts) error {
	if m.ErrReplyToNested != nil {
		return m.ErrReplyToNested
	}

	return nil
}

// SendToDestination mock messenger SendToDestination.
func (m *MockMessenger) SendToDestination(msg service.DIDCommMsgMap, sender string,
	destination *service.Destination, opts ...service.Opt) error {
	if m.ErrSendToDestination != nil {
		return m.ErrSendToDestination
	}

	return nil
}
