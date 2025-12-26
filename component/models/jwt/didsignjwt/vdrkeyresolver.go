package didsignjwt

import (
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
)

type PublicKeyFetcher func(issuerID, keyID string) (*sigapi.PublicKey, error)

type VDRKeyResolver struct {
	vdr didResolver
}
