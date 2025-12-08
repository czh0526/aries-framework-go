package verifiable

import "github.com/czh0526/aries-framework-go/pkg/controller/rest"

type Operation struct {
	handlers []rest.Handler
	command  *verifiablecmd.Command
}
