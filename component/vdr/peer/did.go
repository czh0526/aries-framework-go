package peer

import (
	"encoding/json"
	"errors"
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"strings"
)

const (
	numAlgo = "1"

	transform = multibase.Base58BTC

	peerPrefix = "did:peer:"

	DIDMethod = "peer"
)

func NewDoc(publicKey []didmodel.VerificationMethod, opts ...didmodel.DocOption) (*didmodel.Doc, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("the did:peer genesis version must include public keys and authentication")
	}

	doc := didmodel.BuildDoc(
		append([]didmodel.DocOption{
			didmodel.WithVerificationMethod(publicKey),
		}, opts...)...)

	if len(doc.Authentication) == 0 || len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("the did:peer genesis version must include public keys and authentication")
	}

	id, err := computeDidMethod1(doc)
	if err != nil {
		return nil, err
	}

	doc.ID = id

	return doc, nil
}

func computeDidMethod1(doc *didmodel.Doc) (string, error) {
	if doc.VerificationMethod == nil || doc.Authentication == nil {
		return "", errors.New("the genesis version must include public keys and authentication")
	}

	encNumBasis, err := calculateEncNumBasis(doc)
	if err != nil {
		return "", err
	}

	messageIdentifier := []string{peerPrefix, encNumBasis}

	return strings.Join(messageIdentifier, ""), nil
}

func calculateEncNumBasis(doc *didmodel.Doc) (string, error) {
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}

	hash, err := multihash.Sum(docBytes, multihash.SHA2_256, -1)
	if err != nil {
		return "", err
	}

	messageIdentifier := []string{numAlgo, string(transform), hash.B58String()}

	return strings.Join(messageIdentifier, ""), nil
}
