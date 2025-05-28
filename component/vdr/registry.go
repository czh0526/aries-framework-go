package vdr

import (
	"errors"
	"fmt"
	modeldid "github.com/czh0526/aries-framework-go/component/models/did"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/component/vdr/peer"
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
	// 找到 method namespace
	didMethod, err := GetDidMethod(did)
	if err != nil {
		return nil, err
	}

	// 构建 DIDMethodOption 集合
	acceptOpts := []spivdr.DIDMethodOption{
		spivdr.WithOption(didAcceptOpt, did),
	}
	acceptOpts = append(acceptOpts, opts...)

	// 遍历 vdr，找到与 didMethod 匹配的 VDR
	vdr, err := r.resolveVDR(didMethod, acceptOpts...)
	if err != nil {
		return nil, err
	}

	// 调用 VDR 的 Read 方法读取 DID 文档
	didDocResolution, err := vdr.Read(did, opts...)
	if err != nil {
		if errors.Is(err, vdrapi.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("did method read failed, err = %v", err)
	}

	return didDocResolution, nil
}

func (r *Registry) Create(didMethod string, didDoc *modeldid.Doc,
	opts ...spivdr.DIDMethodOption) (*modeldid.DocResolution, error) {

	docOpts := &spivdr.DIDMethodOpts{
		Values: make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(docOpts)
	}

	vdr, err := r.resolveVDR(didMethod, opts...)
	if err != nil {
		return nil, err
	}

	didDocResolution, err := vdr.Create(didDoc, r.applyDefaultDocOpts(docOpts, opts...)...)
	if err != nil {
		return nil, err
	}

	return didDocResolution, nil
}

func (r *Registry) Update(didDoc *modeldid.Doc, opts ...spivdr.DIDMethodOption) error {
	didMethod, err := GetDidMethod(didDoc.ID)
	if err != nil {
		return err
	}

	acceptOpts := []spivdr.DIDMethodOption{
		spivdr.WithOption(didAcceptOpt, didDoc.ID),
	}
	acceptOpts = append(acceptOpts, opts...)

	// 遍历 vdr, 找到与 didMethod 匹配的 vdr
	vdr, err := r.resolveVDR(didMethod, acceptOpts...)
	if err != nil {
		return err
	}

	return vdr.Update(didDoc, opts...)
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

func (r *Registry) applyDefaultDocOpts(docOpts *spivdr.DIDMethodOpts,
	opts ...spivdr.DIDMethodOption) []spivdr.DIDMethodOption {

	if docOpts.Values[peer.DefaultServiceType] == nil {
		opts = append(opts, spivdr.WithOption(peer.DefaultServiceType, r.defServiceType))
	}

	if docOpts.Values[peer.DefaultServiceEndpoint] == nil {
		opts = append(opts, spivdr.WithOption(peer.DefaultServiceEndpoint, r.defServiceEndpoint))
	}

	return opts
}

func GetDidMethod(didID string) (string, error) {
	const numPartsDID = 3

	didParts := strings.Split(didID, ":")
	if len(didParts) < numPartsDID {
		return "", fmt.Errorf("wrong format did input: %v", didID)
	}

	return didParts[1], nil
}
