package mock

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	spivdr "github.com/czh0526/aries-framework-go/spi/vdr"
	"time"
)

type VDRegistry struct {
	CreateErr      error
	CreateValue    *did.Doc
	CreateFunc     func(string, *did.Doc, ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	UpdateFunc     func(didDoc *did.Doc, opts ...spivdr.DIDMethodOption) error
	DeactivateFunc func(did string, opts ...spivdr.DIDMethodOption) error
	ResolveFunc    func(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	ResolveErr     error
	ResolveValue   *did.Doc
}

func (m *VDRegistry) Create(method string, didDoc *did.Doc,
	opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
	if m.CreateErr != nil {
		return nil, m.CreateErr
	}

	if m.CreateFunc != nil {
		return m.CreateFunc(method, didDoc, opts...)
	}

	doc := m.CreateValue
	if doc == nil {
		doc = createDefaultDID()
	}
	return &did.DocResolution{DIDDocument: doc}, nil
}

func (m *VDRegistry) Resolve(didID string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error) {
	if m.ResolveFunc != nil {
		return m.ResolveFunc(didID, opts...)
	}

	if m.ResolveErr != nil {
		return nil, m.ResolveErr
	}

	if m.ResolveValue == nil {
		return nil, vdrapi.ErrNotFound
	}

	return &did.DocResolution{
		DIDDocument: m.ResolveValue,
	}, nil
}

func (m *VDRegistry) Update(didDoc *did.Doc, opts ...spivdr.DIDMethodOption) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(didDoc, opts...)
	}

	return nil
}

func (m *VDRegistry) Close() error {
	return nil
}

func createDefaultDID() *did.Doc {
	const (
		didContext = "https://w3id.org/did/v1"
		didID      = "did:local:abc"
		creator    = didID + "#key-1"
		keyType    = "Ed25519VerificationKey2018"
	)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	service := did.Service{
		ID:              "did:example:123456789abcdefghi#did-communication",
		Type:            "did-communication",
		ServiceEndpoint: endpoint.NewDIDCommV1Endpoint("https://agent.example.com/"),
		RecipientKeys:   []string{creator},
		Priority:        0,
	}

	signingKey := did.VerificationMethod{
		ID:         creator,
		Type:       keyType,
		Controller: didID,
		Value:      pubKey,
	}

	createdTime := time.Now()

	return &did.Doc{
		Context:            []string{didContext},
		ID:                 didID,
		VerificationMethod: []did.VerificationMethod{signingKey},
		Service:            []did.Service{service},
		Created:            &createdTime,
	}
}
