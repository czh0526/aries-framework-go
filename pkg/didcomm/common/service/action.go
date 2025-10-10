package service

import "sync"

type Action struct {
	mu    sync.RWMutex
	event chan<- DIDCommAction
}

func (a *Action) ActionEvent() chan<- DIDCommAction {
	a.mu.RLock()
	defer a.mu.RUnlock()
	e := a.event

	return e
}
