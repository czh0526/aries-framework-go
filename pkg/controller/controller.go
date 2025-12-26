package controller

import (
	"fmt"
	"github.com/czh0526/aries-framework-go/pkg/controller/rest"
	kmsrest "github.com/czh0526/aries-framework-go/pkg/controller/rest/kms"
	vdrrest "github.com/czh0526/aries-framework-go/pkg/controller/rest/vdr"
	verifiablerest "github.com/czh0526/aries-framework-go/pkg/controller/rest/verifiable"
	"github.com/czh0526/aries-framework-go/pkg/framework/context"
	ldsvc "github.com/czh0526/aries-framework-go/pkg/ld"
	"net/http"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type allOpts struct {
	httpClient HTTPClient
	ldService  ldsvc.Service
}

type Opt func(opts *allOpts)

type handlerProvider interface {
	GetRESTHandlers() []rest.Handler
}

var _ handlerProvider = (*verifiablerest.Operation)(nil)
var _ handlerProvider = (*vdrrest.Operation)(nil)
var _ handlerProvider = (*kmsrest.Operation)(nil)

//var _ handlerProvider = (*vcwalletrest.Operation)(nil)

func GetRestHandlers(ctx *context.Context, opts ...Opt) ([]rest.Handler, error) {
	restAPIOpts := &allOpts{
		httpClient: http.DefaultClient,
		ldService:  ldsvc.New(ctx),
	}

	for _, opt := range opts {
		opt(restAPIOpts)
	}

	vdrOp, err := vdrrest.New(ctx)
	if err != nil {
		return nil, err
	}

	veriableOp, err := verifiablerest.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create verifiable rest command: %w", err)
	}

	kmsOp := kmsrest.New(ctx)
	// wallet := vcwalletrest.New(ctx)

	var allHandlers []rest.Handler
	allHandlers = append(allHandlers, vdrOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, veriableOp.GetRESTHandlers()...)
	allHandlers = append(allHandlers, kmsOp.GetRESTHandlers()...)

	return allHandlers, nil
}
