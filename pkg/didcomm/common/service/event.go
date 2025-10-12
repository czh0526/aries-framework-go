package service

type DIDCommAction struct {
	ProtocolName string
	Message      DIDCommMsg
	Continue     func(args interface{})
	Stop         func(err error)
	Properties   EventProperties
}

type StateMsgType int

const (
	PreState StateMsgType = iota
	PostState
)

type StateMsg struct {
	ProtocolName string
	Type         StateMsgType
	StateID      string
	Msg          DIDCommMsg
	Properties   EventProperties
}

type EventProperties interface {
	All() map[string]interface{}
}

type ActionEvent interface {
	RegisterActionEvent(ch chan<- DIDCommAction) error
	UnregisterActionEvent(ch chan<- DIDCommAction) error
}

type MsgEvent interface {
	RegisterMsgEvent(ch chan<- StateMsg) error
	UnregisterMsgEvent(ch chan<- StateMsg) error
}

type Event interface {
	ActionEvent
	MsgEvent
}

func AutoExecuteActionEvent(ch chan DIDCommAction) {
	for msg := range ch {
		msg.Continue(&Empty{})
	}
}

type Empty struct{}
