package verifiable

import "github.com/czh0526/aries-framework-go/component/models/verifiable"

type Opt func(o *options)

type options struct {
	MyDID    string
	TheirDID string
}

func WithMyDID(myDID string) Opt {
	return func(o *options) {
		o.MyDID = myDID
	}
}

func WithTheirDID(theirDID string) Opt {
	return func(o *options) {
		o.TheirDID = theirDID
	}
}

type Store interface {
	SaveCredential(name string, vc *verifiable.Credential, opts ...Opt) error
	SavePresentation(name string, vp *verifiable.Presentation, opts ...Opt) error
	GetCredential(id string) (*verifiable.Credential, error)
	GetPresentation(id string) (*verifiable.Presentation, error)
}
