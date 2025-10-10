package didexchange

import (
	"fmt"
	connectionstore "github.com/czh0526/aries-framework-go/pkg/store/connection"
)

const (
	stateNameNoop    = "noop"
	stateNameNull    = "null"
	StateIDInvited   = "invited"
	StateIDRequested = "requested"
	StateIDResponded = "responded"
	StateIDCompleted = "completed"
	StateIDAbandoned = "abandoned"
)

type stateAction func() error

type state interface {
	Name() string
	CanTransitionTo(next state) bool
	ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (
		connRecord *connectionstore.Record, state state, action stateAction, err error)
}

func stateFromName(msgType string) (state, error) {
	switch msgType {
	case InvitationMsgType, oobMsgType:
		return &invited{}, nil
	case RequestMsgType:
		return &requested{}, nil
	case ResponseMsgType:
		return &responded{}, nil
	case AckMsgType, CompleteMsgType:
		return &completed{}, nil
	default:
		return nil, fmt.Errorf("unrecognized message type: %s", msgType)
	}
}

type invited struct{}

func (s *invited) Name() string {
	return StateIDInvited
}

func (s *invited) CanTransitionTo(next state) bool {
	return StateIDRequested == next.Name()
}

func (s *invited) ExecuteInbound(msg *stateMachineMsg, _ string, _ *context) (
	*connectionstore.Record, state, stateAction, error) {
	if msg.Type() != InvitationMsgType && msg.Type() != oobMsgType {
		return nil, nil, nil, fmt.Errorf("illegal msg type %s for state %s", msg.Type(), s.Name())
	}

	return msg.connRecord, &requested{}, func() error { return nil }, nil
}

type requested struct{}

func (s *requested) Name() string {
	return StateIDRequested
}

func (s *requested) CanTransitionTo(next state) bool {
	return StateIDResponded == next.Name()
}

func (s *requested) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

type responded struct{}

func (r responded) Name() string {
	return StateIDResponded
}

func (r responded) CanTransitionTo(next state) bool {
	return StateIDCompleted == next.Name()
}

func (r responded) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

type completed struct{}

func (c completed) Name() string {
	return StateIDCompleted
}

func (c completed) CanTransitionTo(next state) bool {
	return false
}

func (c completed) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

type noOp struct{}

func (n noOp) Name() string {
	return stateNameNoop
}

func (n noOp) CanTransitionTo(next state) bool {
	return false
}

func (n noOp) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

var _ state = (*invited)(nil)
var _ state = (*requested)(nil)
var _ state = (*responded)(nil)
var _ state = (*completed)(nil)
var _ state = (*noOp)(nil)
