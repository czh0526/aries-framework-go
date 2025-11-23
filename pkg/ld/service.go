package ld

import (
	"fmt"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
)

type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

type Service interface {
	AddContexts(documents []ldcontext.Document) error
}

type DefaultService struct {
	contextStore        ldstore.ContextStore
	remoteProviderStore ldstore.RemoteProviderStore
}

func (s *DefaultService) AddContexts(documents []ldcontext.Document) error {
	if err := s.contextStore.Import(documents); err != nil {
		return fmt.Errorf("add contexts: %w", err)
	}

	return nil
}

func New(ctx provider) *DefaultService {
	return &DefaultService{
		contextStore:        ctx.JSONLDContextStore(),
		remoteProviderStore: ctx.JSONLDRemoteProviderStore(),
	}
}
