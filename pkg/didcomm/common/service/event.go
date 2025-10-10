package service

type EventProperties interface {
	All() map[string]interface{}
}

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
