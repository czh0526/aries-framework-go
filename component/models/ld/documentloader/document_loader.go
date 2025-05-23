package documentloader

import (
	"fmt"
	ldcontext "github.com/czh0526/aries-framework-go/component/models/ld/context"
	"github.com/czh0526/aries-framework-go/component/models/ld/context/embed"
	ldstore "github.com/czh0526/aries-framework-go/component/models/ld/store"
	jsonld "github.com/piprate/json-gold/ld"
)

type DocumentLoader struct {
	store                ldstore.ContextStore
	remoteDocumentLoader jsonld.DocumentLoader
}

func (d DocumentLoader) LoadDocument(u string) (*jsonld.RemoteDocument, error) {
	//TODO implement me
	panic("implement me")
}

type documentLoaderOpts struct {
	remoteDocumentLoader jsonld.DocumentLoader
	extraContexts        []ldcontext.Document
	remoteProviders      []RemoteProvider
}

type Opts func(opts *documentLoaderOpts)

func WithRemoteDocumentLoader(loader jsonld.DocumentLoader) Opts {
	return func(opts *documentLoaderOpts) {
		opts.remoteDocumentLoader = loader
	}
}

func WithExtraContexts(contexts ...ldcontext.Document) Opts {
	return func(opts *documentLoaderOpts) {
		opts.extraContexts = contexts
	}
}

func WithRemoteProvider(provider RemoteProvider) Opts {
	return func(opts *documentLoaderOpts) {
		opts.remoteProviders = append(opts.remoteProviders, provider)
	}
}

type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

func NewDocumentLoader(ctx provider, opts ...Opts) (*DocumentLoader, error) {
	loaderOpts := &documentLoaderOpts{}

	for _, option := range opts {
		option(loaderOpts)
	}

	contexts, err := prepareContexts(
		ctx.JSONLDRemoteProviderStore(),
		loaderOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("prepare contexts failed, err = %w", err)
	}

	// 向 context store 导入远程数据
	store := ctx.JSONLDContextStore()
	if err = store.Import(contexts); err != nil {
		return nil, fmt.Errorf("import contexts failed, err = %w", err)
	}

	return &DocumentLoader{
		store:                store,
		remoteDocumentLoader: loaderOpts.remoteDocumentLoader,
	}, nil
}

func prepareContexts(providerStore ldstore.RemoteProviderStore,
	opts *documentLoaderOpts) ([]ldcontext.Document, error) {
	m := make(map[string]ldcontext.Document)

	for _, c := range append(embed.Contexts, opts.extraContexts...) {
		m[c.URL] = c
	}

	for _, p := range opts.remoteProviders {
		contexts, err := p.Contexts()
		if err != nil {
			return nil, fmt.Errorf("get contexts from remote provider failed, err = %w", err)
		}

		for _, c := range contexts {
			m[c.URL] = c
		}

		if _, err = providerStore.Save(p.Endpoint()); err != nil {
			return nil, fmt.Errorf("save remote provider failed, err = %w", err)
		}
	}

	var contexts []ldcontext.Document
	for _, c := range m {
		contexts = append(contexts, c)
	}

	return contexts, nil
}
