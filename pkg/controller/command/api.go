package command

import "io"

type Exec func(rw io.Writer, req io.Reader) Error

type Handler interface {
	Name() string
	Method() string
	Handle() Exec
}
