package packager

import "github.com/czh0526/aries-framework-go/pkg/didcomm/transport"

type Packager struct {
	PackValue   []byte
	PackErr     error
	UnpackValue *transport.Envelope
	UnpackErr   error
}

func (p *Packager) PackMessage(envelope *transport.Envelope) ([]byte, error) {
	return p.PackValue, p.PackErr
}

func (p *Packager) UnpackMessage(encMessage []byte) (*transport.Envelope, error) {
	return p.UnpackValue, p.UnpackErr
}

var _ transport.Packager = (*Packager)(nil)
