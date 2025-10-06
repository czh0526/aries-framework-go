package msghandler

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"github.com/czh0526/aries-framework-go/pkg/framework/aries/api"
	"sync"
)

type MockMsgSvcProvider struct {
	svcs          []dispatcher.MessageService
	RegisterErr   error
	UnRegisterErr error
	lock          sync.RWMutex
}

func (m *MockMsgSvcProvider) Services() []dispatcher.MessageService {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.svcs
}

var _ api.MessageServiceProvider = (*MockMsgSvcProvider)(nil)
