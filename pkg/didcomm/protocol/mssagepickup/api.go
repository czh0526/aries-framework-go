package messagepickup

type ProtocolService interface {
	AddMessage(message []byte, theirDID string) error
}
