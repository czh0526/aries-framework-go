package vdr

import (
	modeldid "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	vdrspi "github.com/czh0526/aries-framework-go/spi/vdr"
	"log"
)

type Registry struct {
	vdr                []vdrapi.VDR
	defServiceEndpoint string
	defServiceType     string
}

func (r *Registry) Resolve(did string, opts ...vdrspi.DIDMethodOption) (*modeldid.DocResolution, error) {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Create(method string, did *modeldid.Doc, opts ...vdrspi.DIDMethodOption) (*modeldid.DocResolution, error) {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Update(did *modeldid.Doc, opts ...vdrspi.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Deactivate(did string, opts ...vdrspi.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Close() error {
	//TODO implement me
	panic("implement me")
}

type Option func(registry *Registry)

func WithVDR(method vdrapi.VDR) Option {
	return func(registry *Registry) {
		registry.vdr = append(registry.vdr, method)
	}
}

func New(opts ...Option) *Registry {
	log.Printf("【default】New vdr Registry")
	baseVDR := &Registry{}

	for _, option := range opts {
		option(baseVDR)
	}

	return baseVDR
}

var registry vdrapi.Registry = (*Registry)(nil)
