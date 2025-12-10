package didsignjwt

import (
	signatureapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
)

type PublicKeyFetcher func(issuerID, keyID string) (*signatureapi.PublicKey, error)

type VDRKeyResolver struct {
	vdr didResolver
}
