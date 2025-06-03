package service

type InboundHandler interface {
	HandleInbound(msg DIDCommMsg, ctx DIDCommContext) (string, error)
}

type OutboundHandler interface {
	HandleOutbound(msg DIDCommMsg, myDID, theirDID string) (string, error)
}

type Handler interface {
	InboundHandler
	OutboundHandler
}
