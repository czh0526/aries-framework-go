package messagepickup

type ClientProvider interface {
	Service(id string) (interface{}, error)
}
