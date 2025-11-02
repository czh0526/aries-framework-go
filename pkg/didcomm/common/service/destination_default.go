package service

import (
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/common/model"
	"github.com/czh0526/aries-framework-go/pkg/internal/didkeyutil"
	"strings"
)

const (
	defaultDIDCommProfile   = "didcomm/aip2;env=rfc19"
	defaultDIDCommV2Profile = "didcomm/v2"
)

func CreateDestination(didDoc *didmodel.Doc) (*Destination, error) {
	if didCommService, ok := didmodel.LookupService(didDoc, vdrapi.DIDCommV2ServiceType); ok {
		return createDIDCommV2Destination(didDoc, didCommService)
	}

	if didCommService, ok := didmodel.LookupService(didDoc, vdrapi.DIDCommServiceType); ok {
		return createDIDCommV1Destination(didDoc, didCommService)
	}

	if didCommService, ok := didmodel.LookupService(didDoc, vdrapi.LegacyServiceType); ok {
		return createLegacyDestination(didDoc, didCommService)
	}

	return nil, fmt.Errorf("create destination: missing DID doc service")
}

func createDIDCommV2Destination(didDoc *didmodel.Doc, didCommService *didmodel.Service) (*Destination, error) {
	var (
		accept      []string
		recKeys     []string
		routingKeys []string
		uri         string
		sp          endpoint.Endpoint
		err         error
	)

	for _, ka := range didDoc.KeyAgreement {
		keyID := ka.VerificationMethod.ID
		if strings.HasPrefix(keyID, "#") {
			keyID = didDoc.ID + keyID
		}

		recKeys = append(recKeys, keyID)
	}

	if len(recKeys) == 0 {
		return nil, fmt.Errorf("create destination: no keyAgreements in did doc for didcomm v2 service block. DIDDoc: %+v", didDoc)
	}

	if accept, err = didCommService.ServiceEndpoint.Accept(); len(accept) == 0 || err != nil {
		accept = []string{
			defaultDIDCommV2Profile,
		}
	}

	uri, err = didCommService.ServiceEndpoint.URI()
	if err != nil {
		return nil, fmt.Errorf("create destination: failed to resolve DID service endpoint URI for didcomm v2: %+v, %w", didDoc, err)
	}

	routingKeys, err = didCommService.ServiceEndpoint.RoutingKeys()
	if err != nil {
		routingKeys = nil
	}

	sp = model.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{
		{
			URI:         uri,
			Accept:      accept,
			RoutingKeys: routingKeys,
		},
	})

	return &Destination{
		RecipientKeys:     recKeys,
		ServiceEndpoint:   sp,
		RoutingKeys:       didCommService.RoutingKeys,
		MediaTypeProfiles: didCommService.Accept,
		DIDDoc:            didDoc,
	}, nil
}

func createDIDCommV1Destination(didDoc *didmodel.Doc, didCommService *didmodel.Service) (*Destination, error) {
	uri, err := didCommService.ServiceEndpoint.URI()
	if err != nil {
		return nil, fmt.Errorf("create destination: service endpoint URI on didcomm v1 service block in did doc error: %+v, %w", didDoc, err)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in diddoc: %+v", didDoc)
	}

	for i, k := range didCommService.RecipientKeys {
		if !strings.HasPrefix(k, "did:") {
			return nil, fmt.Errorf("create destination: recipient key %d:[%v] of didComm '%s' not a did:key",
				i+1, k, didCommService.ID)
		}
	}

	if len(didCommService.Accept) == 0 {
		didCommService.Accept = []string{defaultDIDCommProfile}
	}

	sp := model.NewDIDCommV1Endpoint(uri)

	return &Destination{
		RecipientKeys:     didCommService.RecipientKeys,
		ServiceEndpoint:   sp,
		RoutingKeys:       didCommService.RoutingKeys,
		MediaTypeProfiles: didCommService.Accept,
		DIDDoc:            didDoc,
	}, nil
}

func createLegacyDestination(didDoc *didmodel.Doc, didCommService *didmodel.Service) (*Destination, error) {
	uri, err := didCommService.ServiceEndpoint.URI()
	if uri == "" || err != nil {
		return nil, fmt.Errorf("create destination: no service endpoint on didcomm service block in did doc: %#v", didDoc)
	}

	if len(didCommService.RecipientKeys) == 0 {
		return nil, fmt.Errorf("create destination: no recipient keys on didcomm service block in did doc: %#v", didDoc)
	}

	if len(didCommService.Accept) == 0 {
		didCommService.Accept = []string{vdrapi.LegacyServiceType}
	}

	return &Destination{
		RecipientKeys:     didkeyutil.ConvertBase58KeysToDIDKeys(didCommService.RecipientKeys),
		ServiceEndpoint:   model.NewDIDCommV1Endpoint(uri),
		RoutingKeys:       didkeyutil.ConvertBase58KeysToDIDKeys(didCommService.RoutingKeys),
		MediaTypeProfiles: didCommService.Accept,
	}, nil
}
