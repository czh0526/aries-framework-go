package service

type DIDCommContext interface {
	MyDID() string
	TheirDID() string
	EventProperties
}

type DIDCommMsg interface {
	ID() string
	SetID(id string, opts ...Opt)
	SetThread(thid, pthid string, opts ...Opt)
	UnsetThread()
	Type() string
	ThreadID() (string, error)
	ParentThreadID() string
	Clone() DIDCommMsgMap
	Metadata() map[string]interface{}
	Decode(v interface{}) error
}
