package mediator

type Config struct {
	routerEndpoint string
	routingKeys    []string
}

func NewConfig(endpoint string, keys []string) *Config {
	return &Config{
		routerEndpoint: endpoint,
		routingKeys:    keys,
	}
}
