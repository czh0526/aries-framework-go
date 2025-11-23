package msghandler

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/dispatcher"
	"sync"
)

const (
	errAlreadyRegistered = "registration failed, message service with name `%s` already registerd"
	errNvrRegistered     = "failed to unregister, unable to find registered message service with name `%s`"
)

type Registrar struct {
	services []dispatcher.MessageService
	lock     sync.RWMutex
}

func NewRegistrar() *Registrar {
	return &Registrar{}
}

func (m *Registrar) Services() []dispatcher.MessageService {
	m.lock.RLock()
	defer m.lock.RUnlock()

	svcs := make([]dispatcher.MessageService, len(m.services))
	copy(svcs, m.services)

	return svcs
}

func (m *Registrar) Register(msgServices ...dispatcher.MessageService) error {
	if len(msgServices) == 0 {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	if len(m.services) == 0 {
		m.services = append(m.services, msgServices...)
		return nil
	}

	for _, newMsgSvc := range msgServices {
		for _, existingSvc := range m.services {
			if existingSvc.Name() == newMsgSvc.Name() {
				return fmt.Errorf(errAlreadyRegistered, newMsgSvc.Name())
			}
		}
	}

	m.services = append(m.services, msgServices...)
	return nil
}

func (m *Registrar) Unregister(name string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	index := -1
	for i, svc := range m.services {
		if svc.Name() == name {
			index = i
			break
		}
	}

	if index < 0 {
		return fmt.Errorf(errNvrRegistered, name)
	}
	
	m.services = append(m.services[:index], m.services[index+1:]...)
	return nil
}
