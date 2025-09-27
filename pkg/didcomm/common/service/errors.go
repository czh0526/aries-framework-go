package service

const (
	ErrChannelRegistered = serviceError("channel is already registered for the action event")
	ErrNilChannel        = serviceError("cannot pass nil channel")
	ErrInvalidChannel    = serviceError("invalid channel passed to unregister the action event")
	ErrThreadIDNotFound  = serviceError("threadID not found")
	ErrInvalidMessage    = serviceError("invalid message")
	ErrNilMessage        = serviceError("message is nil")
)

type serviceError string

func (e serviceError) Error() string {
	return string(e)
}
