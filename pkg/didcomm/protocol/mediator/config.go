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

func (c *Config) Endpoint() string {
	return c.routerEndpoint
}

func (c *Config) Keys() []string {
	return c.routingKeys
}
