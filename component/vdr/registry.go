package vdr

import (
	"errors"
	"fmt"
	modeldid "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"log"
	"strings"
)

const didAcceptOpt = "didAcceptOpt"

type Registry struct {
	vdr                []vdrapi.VDR
	defServiceEndpoint string
	defServiceType     string
}

type Option func(registry *Registry)

func New(opts ...Option) *Registry {
	log.Printf("【default】New vdr Registry")
	baseVDR := &Registry{}

	for _, option := range opts {
		option(baseVDR)
	}

	return baseVDR
}

var _ vdrapi.Registry = (*Registry)(nil)

func WithVDR(method vdrapi.VDR) Option {
	return func(registry *Registry) {
		registry.vdr = append(registry.vdr, method)
	}
}

func WithDefaultServiceEndpoint(endpoint string) Option {
	return func(registry *Registry) {
		registry.defServiceEndpoint = endpoint
	}
}

func WithDefaultServiceType(serviceType string) Option {
	return func(registry *Registry) {
		registry.defServiceType = serviceType
	}
}

func (r *Registry) Resolve(did string, opts ...spivdr.DIDMethodOption) (*modeldid.DocResolution, error) {
	didMethod, err := GetDidMethod(did)
	if err != nil {
		return nil, err
	}

	acceptOpts := []spivdr.DIDMethodOption{
		spivdr.WithOption(didAcceptOpt, did),
	}
	acceptOpts = append(acceptOpts, opts...)

	method, err := r.resolveVDR(didMethod, acceptOpts...)
	if err != nil {
		return nil, err
	}

	didDocResolution, err := method.Read(did, opts...)
	if err != nil {
		if errors.Is(err, vdrapi.ErrNotFound) {
			return nil, err
		}
	}

	return didDocResolution, nil
}

func (r *Registry) Create(method string, did *modeldid.Doc, opts ...spivdr.DIDMethodOption) (*modeldid.DocResolution, error) {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Update(did *modeldid.Doc, opts ...spivdr.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Deactivate(did string, opts ...spivdr.DIDMethodOption) error {
	//TODO implement me
	panic("implement me")
}

func (r *Registry) Close() error {
	for _, v := range r.vdr {
		if err := v.Close(); err != nil {
			return fmt.Errorf("close vdr: %v", err)
		}
	}
	return nil
}

func (r *Registry) resolveVDR(method string, opts ...spivdr.DIDMethodOption) (vdrapi.VDR, error) {
	for _, v := range r.vdr {
		if v.Accept(method, opts...) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("did method %s not supported for vdr", method)
}

func GetDidMethod(didID string) (string, error) {
	const numPartsDID = 3

	didParts := strings.Split(didID, ":")
	if len(didParts) < numPartsDID {
		return "", fmt.Errorf("wrong format did input: %v", didID)
	}

	return didParts[1], nil
}
