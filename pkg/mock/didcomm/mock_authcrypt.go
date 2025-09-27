package didcomm

import (
	"github.com/czh0526/aries-framework-go/pkg/didcomm/packer"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
)

type MockAuthCrypt struct {
	EncryptValue func(cty string, payload, senderPubKey []byte, recipients [][]byte) ([]byte, error)
	DecryptValue func(envelope []byte) (*transport.Envelope, error)
	Type         string
}

func (m *MockAuthCrypt) Pack(contentType string, payload []byte, senderKey []byte, recipients [][]byte) (envelope []byte, err error) {
	return m.EncryptValue(contentType, payload, senderKey, recipients)
}

func (m *MockAuthCrypt) Unpack(envelope []byte) (*transport.Envelope, error) {
	return m.DecryptValue(envelope)
}

func (m *MockAuthCrypt) EncodingType() string {
	return m.Type
}

var _ packer.Packer = (*MockAuthCrypt)(nil)
