package did

import (
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/models/did/endpoint"
	"strings"
)

type Service struct {
	ID                       string
	Type                     interface{}
	Priority                 interface{}
	RecipientKeys            []string
	RoutingKeys              []string
	ServiceEndpoint          endpoint.Endpoint
	Accept                   []string
	Properties               map[string]interface{}
	recipientKeysRelativeURL map[string]bool
	routingKeysRelativeURL   map[string]bool
	relativeURL              bool
}

func populateServices(didID, baseURI string, rawServices []map[string]interface{}) []Service {
	services := make([]Service, 0, len(rawServices))

	for _, rawService := range rawServices {
		id := stringEntry(rawService[jsonldID])
		recipientKeys := stringArray(rawService[jsonldRecipientKeys])
		routingKeys := stringArray(rawService[jsonldRoutingKeys])

		var recipientKeysRelativeURL map[string]bool
		var routingKeysRelativeURL map[string]bool
		isRelative := false

		if strings.HasPrefix(id, "#") {
			id = resolveRelativeDIDURL(didID, baseURI, id)
			isRelative = true
		}

		if len(recipientKeys) != 0 {
			recipientKeys, recipientKeysRelativeURL = populateKeys(recipientKeys, didID, baseURI)
		}

		if len(routingKeys) != 0 {
			routingKeys, routingKeysRelativeURL = populateKeys(routingKeys, didID, baseURI)
		}

		var sp endpoint.Endpoint

		if epEntry, ok := rawService[jsonldServicePoint]; ok {
			uriStr, ok := epEntry.(string)
			if ok {
				sp = endpoint.NewDIDCommV1Endpoint(uriStr)
			} else if epEntry != nil {
				entries, ok := epEntry.([]interface{})
				if ok && len(entries) > 0 {
					firstEntry, is := entries[0].(map[string]interface{})
					if is {
						epURI := stringEntry(firstEntry["uri"])
						epAccept := stringArray(firstEntry["accept"])
						epRoutingKeys := stringArray(firstEntry["routingkeys"])
						sp = endpoint.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{
							{URI: epURI, Accept: epAccept, RoutingKeys: epRoutingKeys},
						})
					}
				}
				coreServices, ok := epEntry.(map[string]interface{})
				if ok && len(coreServices) > 0 {
					sp = endpoint.NewDIDCoreEndpoint(coreServices)
				}
			}
		}

		service := Service{
			ID:                       id,
			Type:                     rawService[jsonldType],
			relativeURL:              isRelative,
			ServiceEndpoint:          sp,
			RecipientKeys:            recipientKeys,
			Priority:                 rawService[jsonldPriority],
			RoutingKeys:              routingKeys,
			recipientKeysRelativeURL: recipientKeysRelativeURL,
			routingKeysRelativeURL:   routingKeysRelativeURL,
		}

		delete(rawService, jsonldID)
		delete(rawService, jsonldType)
		delete(rawService, jsonldServicePoint)
		delete(rawService, jsonldRecipientKeys)
		delete(rawService, jsonldRoutingKeys)
		delete(rawService, jsonldPriority)

		service.Properties = rawService
		services = append(services, service)
	}

	return services
}

func populateRawServices(services []Service, didID, baseURI string) []map[string]interface{} {
	var rawServices []map[string]interface{}

	for i := range services {
		rawService := make(map[string]interface{})

		for k, v := range services[i].Properties {
			rawService[k] = v
		}

		routingKeys := make([]string, 0)
		for _, v := range services[i].RoutingKeys {
			if services[i].routingKeysRelativeURL[v] {
				routingKeys = append(routingKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}
			routingKeys = append(routingKeys, v)
		}

		sepRoutingKeys, err := services[i].ServiceEndpoint.RoutingKeys()
		if err != nil && len(sepRoutingKeys) > 0 {
			var tmpRoutingKeys []string

			for _, v := range sepRoutingKeys {
				if services[i].routingKeysRelativeURL[v] {
					tmpRoutingKeys = append(tmpRoutingKeys, makeRelativeDIDURL(v, baseURI, didID))
					continue
				}

				tmpRoutingKeys = append(tmpRoutingKeys, v)
			}

			sepRoutingKeys = tmpRoutingKeys
		}

		sepAccept, err := services[i].ServiceEndpoint.Accept()
		if err != nil {
			logger.Debugf("accept field of DIDComm V2 endpoint missing or invalid, it will be ignured: %w", err)
		}

		// service `serviceEndpoint`.`URL`
		sepURI, err := services[i].ServiceEndpoint.URI()
		if err != nil {
			logger.Debugf("URI field of DIDComm V2 endpoint missing or invalid, it will be ignured: %w", err)
		}
		if services[i].ServiceEndpoint.Type() == endpoint.DIDCommV2 {
			services[i].ServiceEndpoint = endpoint.NewDIDCommV2Endpoint(
				[]endpoint.DIDCommV2Endpoint{
					{URI: sepURI, Accept: sepAccept, RoutingKeys: sepRoutingKeys},
				})
		}

		// service `recipientKeys`
		recipientKeys := make([]string, 0)
		for _, v := range services[i].RecipientKeys {
			if services[i].recipientKeysRelativeURL[v] {
				recipientKeys = append(recipientKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}
			recipientKeys = append(recipientKeys, v)
		}

		// service `id`
		rawService[jsonldID] = services[i].ID
		if services[i].relativeURL {
			rawService[jsonldID] = makeRelativeDIDURL(services[i].ID, baseURI, didID)
		}

		// service `type`
		rawService[jsonldType] = services[i].Type

		if services[i].ServiceEndpoint.Type() == endpoint.DIDCommV2 {
			serviceEndpointMap := []map[string]interface{}{
				{"uri": sepURI},
			}
			if len(sepAccept) > 0 {
				serviceEndpointMap[0]["accept"] = sepAccept
			}

			if len(sepRoutingKeys) > 0 {
				serviceEndpointMap[0]["routingKeys"] = sepRoutingKeys
			}

			rawService[jsonldServicePoint] = serviceEndpointMap

		} else if services[i].ServiceEndpoint.Type() == endpoint.DIDCommV1 {
			rawService[jsonldServicePoint] = sepURI
		} else {
			bytes, err := services[i].ServiceEndpoint.MarshalJSON()
			if err != nil {
				logger.Warnf(err.Error())
			}

			rawService[jsonldServicePoint] = json.RawMessage(bytes)
		}

		if services[i].Priority != nil {
			rawService[jsonldPriority] = services[i].Priority
		}

		if len(recipientKeys) > 0 {
			rawService[jsonldRecipientKeys] = recipientKeys
		}

		if len(routingKeys) > 0 {
			rawService[jsonldRoutingKeys] = routingKeys
		}

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}

func populateKeys(keys []string, didID, baseURI string) ([]string, map[string]bool) {
	values := make([]string, 0)
	keysRelativeURL := make(map[string]bool)

	for _, v := range keys {
		if strings.HasPrefix(v, "#") {
			id := resolveRelativeDIDURL(didID, baseURI, v)
			values = append(values, id)
			keysRelativeURL[id] = true

			continue
		}

		keysRelativeURL[v] = false
		values = append(values, v)
	}

	return values, keysRelativeURL
}
