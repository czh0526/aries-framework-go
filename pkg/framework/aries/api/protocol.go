package api

import "github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"

type MessageServiceProvider interface {
	Services() []dispatcher.MessageService
}
