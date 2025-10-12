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

func (a *Action) RegisterActionEvent(ch chan<- DIDCommAction) error {
	if ch == nil {
		return ErrNilChannel
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.event != nil {
		return ErrChannelRegistered
	}
	a.event = ch

	return nil
}

func (a *Action) UnregisterActionEvent(ch chan<- DIDCommAction) error {
	if ch == nil {
		return ErrNilChannel
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.event != ch {
		return ErrInvalidChannel
	}
	a.event = nil

	return nil
}
