package service

import "sync"

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
