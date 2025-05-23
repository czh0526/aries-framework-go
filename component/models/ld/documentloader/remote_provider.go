package documentloader

import ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"

type RemoteProvider interface {
	Endpoint() string
	Contexts() ([]ldcontext.Document, error)
}
