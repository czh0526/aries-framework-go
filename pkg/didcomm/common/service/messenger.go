package service

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

type DIDCommContext interface {
	MyDID() string
	TheirDID() string
	EventProperties
}

type context struct {
	myDID    string
	theirDID string
	props    map[string]interface{}
}

func (c *context) MyDID() string {
	return c.myDID
}

func (c *context) TheirDID() string {
	return c.theirDID
}

func (c *context) All() map[string]interface{} {
	return c.props
}

func NewDIDCommContext(myDID, theirDID string, props map[string]interface{}) DIDCommContext {
	return &context{
		myDID:    myDID,
		theirDID: theirDID,
		props:    props,
	}
}

func EmptyDIDCommContext() DIDCommContext {
	return &context{
		props: make(map[string]interface{}),
	}
}

type Messenger interface {
	ReplyTo(msgID string, msg DIDCommMsgMap, opts ...Opt) error

	ReplyToMsg(in, out DIDCommMsgMap, myDID, theirDID string, opts ...Opt) error

	Send(msg DIDCommMsgMap, myDID, theirDID string, opts ...Opt) error

	SendToDestination(msg DIDCommMsgMap, sender string, destination *Destination, opts ...Opt) error
}

type InboundMessenger interface {
	HandleInbound(msg DIDCommMsgMap, ctx DIDCommContext) error
}

type MessengerHandler interface {
	Messenger
	InboundMessenger
}

type NestedReplyOpts struct {
	ThreadID string
	MyDID    string
	TheirDID string
	MsgID    string
	V        Version
}
