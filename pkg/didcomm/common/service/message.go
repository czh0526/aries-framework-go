package service

import (
	"sync"
)

type Message struct {
	mu     sync.RWMutex
	events []chan<- StateMsg
}

func (m *Message) MsgEvents() []chan<- StateMsg {
	m.mu.RLock()
	events := append(m.events[:0:0], m.events...)
	defer m.mu.RUnlock()

	return events
}

func (m *Message) RegisterMsgEvent(ch chan<- StateMsg) error {
	if ch == nil {
		return ErrNilChannel
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.events = append(m.events, ch)

	return nil
}

func (m *Message) UnregisterMsgEvent(ch chan<- StateMsg) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := 0; i < len(m.events); i++ {
		if m.events[i] == ch {
			m.events = append(m.events[:i], m.events[i+1:]...)
			i--
		}
	}

	return nil
}
