package peer

import (
	"github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/vdr/peer"
)

const (
	StoreNamespace = "peer"
	DIDMethod      = "peer"
)

func UnsignedGenesisDelta(doc *did.Doc) (string, error) {
	return peer.UnsignedGenesisDelta(doc)
}
