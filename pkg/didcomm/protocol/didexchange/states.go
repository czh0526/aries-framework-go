package didexchange

import (
	"errors"
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

func stateFromMsgType(msgType string) (state, error) {
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
		return nil, fmt.Errorf("unrecognized msgType: %s", msgType)
	}
}

func stateFromName(name string) (state, error) {
	switch name {
	case stateNameNoop:
		return &noOp{}, nil
	case stateNameNull:
		return &null{}, nil
	case StateIDInvited:
		return &invited{}, nil
	case StateIDRequested:
		return &requested{}, nil
	case StateIDResponded:
		return &responded{}, nil
	case StateIDCompleted:
		return &completed{}, nil
	case StateIDAbandoned:
		return &abandoned{}, nil
	default:
		return nil, fmt.Errorf("invalid state name: %s", name)
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

func (r *responded) Name() string {
	return StateIDResponded
}

func (r *responded) CanTransitionTo(next state) bool {
	return StateIDCompleted == next.Name()
}

func (r *responded) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

type completed struct{}

func (c *completed) Name() string {
	return StateIDCompleted
}

func (c *completed) CanTransitionTo(next state) bool {
	return false
}

func (c *completed) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

type abandoned struct{}

func (a abandoned) Name() string {
	return StateIDAbandoned
}

func (a abandoned) CanTransitionTo(next state) bool {
	return false
}

func (a abandoned) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (connRecord *connectionstore.Record, state state, action stateAction, err error) {
	//TODO implement me
	panic("implement me")
}

type noOp struct{}

func (n *noOp) Name() string {
	return stateNameNoop
}

func (n *noOp) CanTransitionTo(next state) bool {
	return false
}

func (n *noOp) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (
	connRecord *connectionstore.Record, state state, action stateAction, err error) {
	return nil, nil, nil, errors.New("cannot execute no-op")
}

type null struct{}

func (n *null) Name() string {
	return stateNameNull
}

func (n *null) CanTransitionTo(next state) bool {
	return StateIDInvited == next.Name() || StateIDRequested == next.Name()
}

func (n *null) ExecuteInbound(msg *stateMachineMsg, thid string, ctx *context) (
	connRecord *connectionstore.Record, state state, action stateAction, err error) {
	return &connectionstore.Record{}, &noOp{}, nil, nil
}

var _ state = (*invited)(nil)
var _ state = (*requested)(nil)
var _ state = (*responded)(nil)
var _ state = (*completed)(nil)
var _ state = (*abandoned)(nil)
var _ state = (*noOp)(nil)
var _ state = (*null)(nil)
