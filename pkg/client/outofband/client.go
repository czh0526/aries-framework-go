package outofband

import (
	"fmt"
	didmodel "github.com/czh0526/aries-framework-go/component/models/did"
	endpointmodel "github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	vdrapi "github.com/czh0526/aries-framework-go/component/vdr/api"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/common/service"
	medprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/mediator"
	oobprotocol "github.com/czh0526/aries-framework-go/pkg/didcomm/protocol/outofband"
	"github.com/czh0526/aries-framework-go/pkg/didcomm/transport"
	oobprovider "github.com/czh0526/aries-framework-go/provider/outofband"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"github.com/google/uuid"
)

type OobService interface {
	service.Event
	AcceptInvitation(*oobprotocol.Invitation, oobprotocol.Options) (string, error)
	SaveInvitation(*oobprotocol.Invitation) error
	Actions() []oobprotocol.Action
}

type Client struct {
	service.Event
	didDocSvcFunc     func(routerConnID string, accept []string) (*didmodel.Service, error)
	oobService        OobService
	mediaTypeProfiles []string
}

func New(p oobprovider.Provider) (*Client, error) {
	s, err := p.Service(oobprotocol.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to look up service %s: %w", oobprotocol.Name, err)
	}

	oobSvc, ok := s.(OobService)
	if !ok {
		return nil, fmt.Errorf("failed to cast service `%s` to OobService", oobprotocol.Name)
	}

	mtp := p.MediaTypeProfiles()
	if len(mtp) == 0 {
		mtp = []string{
			transport.MediaTypeAIP2RFC0019Profile,
		}
	}

	client := &Client{
		Event:             oobSvc,
		oobService:        oobSvc,
		mediaTypeProfiles: mtp,
	}

	client.didDocSvcFunc = client.didServiceBlockFunc(p)

	return client, nil
}

func (c *Client) didServiceBlockFunc(p oobprovider.Provider) func(routerConnID string, accept []string) (*didmodel.Service, error) {
	return func(routerConnID string, accept []string) (*didmodel.Service, error) {
		var (
			keyType            spikms.KeyType
			didCommServiceType string
			sp                 endpointmodel.Endpoint
		)

		useDIDCommV2 := isDIDCommV2(accept)
		if useDIDCommV2 {
			keyType = p.KeyAgreementType()
			didCommServiceType = vdrapi.DIDCommV2ServiceType
			sp = endpointmodel.NewDIDCommV2Endpoint([]endpointmodel.DIDCommV2Endpoint{
				{
					URI:    p.ServiceEndpoint(),
					Accept: p.MediaTypeProfiles(),
				},
			})
		} else {
			keyType = p.KeyType()
			didCommServiceType = vdrapi.DIDCommServiceType
			sp = endpointmodel.NewDIDCommV1Endpoint(p.ServiceEndpoint())
		}

		var svc *didmodel.Service

		if useDIDCommV2 {
			sp = endpointmodel.NewDIDCommV2Endpoint([]endpointmodel.DIDCommV2Endpoint{
				{
					URI:    p.ServiceEndpoint(),
					Accept: p.MediaTypeProfiles(),
				},
			})
			svc = &didmodel.Service{
				ID:            uuid.New().String(),
				Type:          didCommServiceType,
				RecipientKeys: []string{didKey},
			}
		} else {
			sp = endpointmodel.NewDIDCommV1Endpoint(p.ServiceEndpoint())
		}
	}
}

func isDIDCommV2(accept []string) bool {
	for _, a := range accept {
		switch a {
		case transport.MediaTypeDIDCommV2Profile, transport.MediaTypeAIP2RFC0587Profile,
			transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
			transport.MediaTypeV1EncryptedEnvelope:
			return true
		}
	}

	return false
}
