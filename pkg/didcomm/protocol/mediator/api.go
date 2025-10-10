package mediator

type ProtocolService interface {
	AddKey(connID, recKey string) error
	Config(connID string) (*Config, error)
	GetConnections(options ...ConnectionOption) ([]string, error)
}
