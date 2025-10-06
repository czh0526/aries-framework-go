package did

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/log"
	"github.com/xeipuuv/gojsonschema"
	"strings"
	"time"
)

const (
	ContextV1     = "https://www.w3,org/ns/did/v1"
	ContextV1Old  = "https://w3id.org/did/v1"
	contextV011   = "https://w3id.org/did/v0.11"
	contextV12019 = "https://www.w3.org/2019/did/v1"

	jsonldType          = "type"
	jsonldID            = "id"
	jsonldPublicKey     = "publicKey"
	jsonldServicePoint  = "serviceEndpoint"
	jsonldRecipientKeys = "recipientKeys"
	jsonldRoutingKeys   = "routingKeys"
	jsonldPriority      = "priority"
	jsonldController    = "controller"
	jsonldOwner         = "owner"

	jsonldCreator        = "creator"
	jsonldCreated        = "created"
	jsonldProofValue     = "proofValue"
	jsonldSignatureValue = "signatureValue"
	jsonldDomain         = "domain"
	jsonldNonce          = "nonce"
	jsonldProofPurpose   = "proofPurpose"

	// various public key encodings.
	jsonldPublicKeyBase58    = "publicKeyBase58"
	jsonldPublicKeyMultibase = "publicKeyMultibase"
	jsonldPublicKeyHex       = "publicKeyHex"
	jsonldPublicKeyPem       = "publicKeyPem"
	jsonldPublicKeyjwk       = "publicKeyJwk"

	legacyServiceType = "IndyAgent"
)

var (
	schemaLoaderV1     = gojsonschema.NewStringLoader(schemaV1)
	schemaLoaderV011   = gojsonschema.NewStringLoader(schemaV011)
	schemaLoaderV12019 = gojsonschema.NewStringLoader(schemaV12019)
	logger             = log.New("aries-framework/doc/did")
)

type Context interface{}

type processingMeta struct {
	baseURI string
}

type Doc struct {
	Context              Context
	ID                   string
	AlsoKnownAs          []string
	VerificationMethod   []VerificationMethod
	Service              []Service
	Authentication       []Verification
	AssertionMethod      []Verification
	CapabilityDelegation []Verification
	CapabilityInvocation []Verification
	KeyAgreement         []Verification
	Created              *time.Time
	Updated              *time.Time
	Proof                []Proof
	processingMeta       processingMeta
}

type rawDoc struct {
	Context              Context                  `json:"@context,omitempty"`
	ID                   string                   `json:"id,omitempty"`
	AlsoKnownAs          []interface{}            `json:"alsoKnownAs,omitempty"`
	VerificationMethod   []map[string]interface{} `json:"verificationMethod,omitempty"`
	PublicKey            []map[string]interface{} `json:"publicKey,omitempty"`
	Service              []map[string]interface{} `json:"service,omitempty"`
	Authentication       []interface{}            `json:"authentication,omitempty"`
	AssertionMethod      []interface{}            `json:"assertionMethod,omitempty"`
	CapabilityDelegation []interface{}            `json:"capabilityDelegation,omitempty"`
	CapabilityInvocation []interface{}            `json:"capabilityInvocation,omitempty"`
	KeyAgreement         []interface{}            `json:"keyAgreement,omitempty"`
	Created              *time.Time               `json:"created,omitempty"`
	Updated              *time.Time               `json:"updated,omitempty"`
	Proof                []interface{}            `json:"proof,omitempty"`
}

func (r *rawDoc) schemaLoader() gojsonschema.JSONLoader {
	context, _ := ContextPeekString(r.Context)
	switch context {
	case contextV011:
		return schemaLoaderV011
	case contextV12019:
		return schemaLoaderV12019
	default:
		return schemaLoaderV1
	}
}

func ParseDocument(data []byte) (*Doc, error) {
	raw := &rawDoc{}

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of did doc bytes failed: %w", err)
	} else if raw == nil {
		return nil, errors.New("document payload is not provided")
	}

	var serviceType string
	if len(raw.Service) > 0 {
		serviceType, _ = raw.Service[0]["type"].(string)
	}

	if (doACAPYInterop || serviceType == legacyServiceType) && requiresLegacyHandling(raw) {
		raw.Context = []string{contextV011}
	} else {
		err = validate(data, raw.schemaLoader())
		if err != nil {
			return nil, err
		}
	}

	doc := &Doc{
		ID:          raw.ID,
		AlsoKnownAs: stringArray(raw.AlsoKnownAs),
		Created:     raw.Created,
		Updated:     raw.Updated,
	}

	context, baseURI := parseContext(raw.Context)
	doc.Context = context
	doc.processingMeta = processingMeta{baseURI: baseURI}
	doc.Service = populateServices(raw.ID, baseURI, raw.Service)

	verificationMethod := raw.PublicKey
	if len(raw.VerificationMethod) > 0 {
		verificationMethod = raw.VerificationMethod
	}

	schema, _ := ContextPeekString(context)

	vm, err := populateVerificationMethod(schema, doc.ID, baseURI, verificationMethod)
	if err != nil {
		return nil, fmt.Errorf("populate verification method failed: %w", err)
	}

	doc.VerificationMethod = vm

	err = populateVerificationRelationships(doc, raw)
	if err != nil {
		return nil, err
	}

	proofs, err := populateProofs(schema, doc.ID, baseURI, raw.Proof)
	if err != nil {
		return nil, fmt.Errorf("populate proof failed: %w", err)
	}

	doc.Proof = proofs
	return doc, nil
}

func (doc *Doc) JSONBytes() ([]byte, error) {
	context, ok := ContextPeekString(doc.Context)
	if !ok {
		context = ContextV1
	}

	aka := populateRawAlsoKnownAs(doc.AlsoKnownAs)

	vm, err := populateRawVM(context, doc.ID, doc.processingMeta.baseURI,
		doc.VerificationMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Verification Method failed: %v", err)
	}

	auths, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.Authentication)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Authentication failed: %v", err)
	}

	assertionMethods, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of AssertionMethod failed: %v", err)
	}

	capabilityDelegations, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityDelegation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityDelegation failed: %v", err)
	}

	capabilityInvocation, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityInvocation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityInvocation failed: %v", err)
	}

	keyAgreements, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of KeyAgreement failed: %v", err)
	}

	raw := &rawDoc{
		Context:              doc.Context,
		ID:                   doc.ID,
		AlsoKnownAs:          aka,
		VerificationMethod:   vm,
		Authentication:       auths,
		AssertionMethod:      assertionMethods,
		CapabilityDelegation: capabilityDelegations,
		CapabilityInvocation: capabilityInvocation,
		KeyAgreement:         keyAgreements,
		Service:              populateRawServices(doc.Service, doc.ID, doc.processingMeta.baseURI),
		Created:              doc.Created,
		Proof:                populateRawProofs(context, doc.ID, doc.processingMeta.baseURI, doc.Proof),
		Updated:              doc.Updated,
	}

	if doc.processingMeta.baseURI != "" {
		raw.Context = contextWithBase(doc)
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of rawDoc failed: %v", err)
	}

	return byteDoc, nil
}

func populateRawAlsoKnownAs(aka []string) []interface{} {
	rawAka := make([]interface{}, len(aka))

	for i, v := range aka {
		rawAka[i] = v
	}

	return rawAka
}

func requiresLegacyHandling(raw *rawDoc) bool {
	return ContextContainsString(raw.Context, ContextV1Old)
}

func resolveRelativeDIDURL(didID, baseURI string, keyID interface{}) string {
	id := baseURI

	if id == "" {
		id = didID
	}

	return id + keyID.(string)
}

func makeRelativeDIDURL(didURL, baseURI, didID string) string {
	id := baseURI

	if id == "" {
		id = didID
	}

	return strings.Replace(didURL, id, "", 1)
}

func parseContext(context Context) (Context, string) {
	context = ContextCopy(context)

	switch ctx := context.(type) {
	case string, []string:
		return ctx, ""
	case []interface{}:
		var newContext []interface{}

		var base string

		for _, v := range ctx {
			switch value := v.(type) {
			case string:
				newContext = append(newContext, value)
			case map[string]interface{}:
				if baseValue, ok := value["@base"].(string); ok {
					base = baseValue
				}

				delete(value, "@base")

				if len(value) > 0 {
					newContext = append(newContext, value)
				}
			}
		}

		return ContextCleanup(newContext), base
	}

	return "", ""
}

func contextWithBase(doc *Doc) Context {
	baseObject := make(map[string]interface{})
	baseObject["@context"] = doc.processingMeta.baseURI

	m := make([]interface{}, 0)

	switch ctx := doc.Context.(type) {
	case string:
		m = append(m, ctx)
	case []string:
		for _, item := range ctx {
			m = append(m, item)
		}
	case []interface{}:
		if len(ctx) > 0 {
			m = append(m, ctx)
		}
	}

	m = append(m, baseObject)

	return m
}

type DocResolution struct {
	Context          Context
	DIDDocument      *Doc
	DocumentMetadata *DocumentMetadata
}

func validate(data []byte, schemaLoader gojsonschema.JSONLoader) error {
	documentLoader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("validation of DID doc failed: %v", err)
	}

	if !result.Valid() {
		errMsg := "did document not valid:\n"
		for _, desc := range result.Errors() {
			errMsg += fmt.Sprintf("- %s\n", desc)
		}
		errMsg += fmt.Sprintf("Document: %s\n", string(data))

		return errors.New(errMsg)
	}

	return nil
}

func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}

	if e, ok := entry.(string); ok {
		return e
	}

	return ""
}

func stringArray(entry interface{}) []string {
	if entry == nil {
		return nil
	}

	entries, ok := entry.([]interface{})
	if !ok {
		return nil
	}

	var result []string
	for _, e := range entries {
		if e != nil {
			result = append(result, stringEntry(e))
		}
	}

	return result
}

func mapEntry(entry interface{}) map[string]interface{} {
	if entry == nil {
		return nil
	}

	result, ok := entry.(map[string]interface{})
	if !ok {
		return nil
	}

	return result
}
