package cmdutil

import (
	"github.com/czh0526/aries-framework-go/pkg/controller/command"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	"net/http"
)

type HTTPHandler struct {
	path   string
	method string
	handle http.HandlerFunc
}

func (h *HTTPHandler) Path() string {
	return h.path
}

func (h *HTTPHandler) Method() string {
	return h.method
}

func (h *HTTPHandler) Handle() http.HandlerFunc {
	return h.handle
}

var _ rest.Handler = (*HTTPHandler)(nil)

func NewHTTPHandler(path, method string, handle http.HandlerFunc) *HTTPHandler {
	return &HTTPHandler{
		path:   path,
		method: method,
		handle: handle,
	}
}

type CommandHandler struct {
	name   string
	method string
	handle command.Exec
}

func (c *CommandHandler) Name() string {
	return c.name
}

func (c *CommandHandler) Method() string {
	return c.method
}

func (c *CommandHandler) Handle() command.Exec {
	return c.handle
}

var _ command.Handler = (*CommandHandler)(nil)

func NewCommandHandler(name, method string, exec command.Exec) *CommandHandler {
	return &CommandHandler{
		name:   name,
		method: method,
		handle: exec,
	}
}
