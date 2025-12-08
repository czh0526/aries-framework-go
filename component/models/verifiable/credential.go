package verifiable

import (
	"encoding/json"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	signatureapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"
	"net/http"
)

type Issuer struct {
	ID           string       `json:"id,omitempty"`
	CustomFields CustomFields `json:"customFields,omitempty"`
}

type Evidence interface{}

type Credential struct {
	Context          []string
	CustomContext    []interface{}
	ID               string
	Types            []string
	Subject          interface{}
	Issuer           Issuer
	Issued           *timeutil.TimeWrapper
	Expired          *timeutil.TimeWrapper
	Proofs           []Proof
	Status           *TypedID
	Schemas          []TypedID
	Evidence         Evidence
	TermsOfUse       []TypedID
	RefreshService   []TypedID
	JWT              string
	SDJWTVersion     common.SDJWTVersion
	SDJWTHashAlg     string
	SDJWTDisclosures []*common.DisclosureClaim
	SDHolderBinding  string
	CustomFields     CustomFields
}

type rawCredential struct {
	Context          interface{}           `json:"@context,omitempty"`
	ID               string                `json:"id,omitempty"`
	Type             interface{}           `json:"type,omitempty"`
	Subject          json.RawMessage       `json:"credentialSubject,omitempty"`
	Issued           *timeutil.TimeWrapper `json:"issuanceDate,omitempty"`
	Expired          *timeutil.TimeWrapper `json:"expirationDate,omitempty"`
	Proof            *json.RawMessage      `json:"proof,omitempty"`
	Status           *TypedID              `json:"credentialStatus,omitempty"`
	Issuer           json.RawMessage       `json:"issuer,omitempty"`
	Schema           interface{}           `json:"credentialSchema,omitempty"`
	Evidence         Evidence              `json:"evidence,omitempty"`
	TermsOfUse       json.RawMessage       `json:"termsOfUse,omitempty"`
	RefreshService   json.RawMessage       `json:"refreshService,omitempty"`
	JWT              string                `json:"jwt,omitempty"`
	SDJWTHashAlg     string                `json:"_sd_alg,omitempty"`
	SDJWTDisclosures []string              `json:"-"`
	SDJWTVersion     common.SDJWTVersion   `json:"-"`
	CustomFields     `json:"-"`
}

var _ json.Marshaler = (*rawCredential)(nil)
var _ json.Unmarshaler = (*rawCredential)(nil)

func (rc *rawCredential) MarshalJSON() ([]byte, error) {
	type Alias rawCredential

	alias := (*Alias)(rc)

	return jsonutil.MarshalWithCustomFields(alias, rc.CustomFields)
}

func (rc *rawCredential) UnmarshalJSON(data []byte) error {
	type Alias rawCredential

	alias := (*Alias)(rc)
	rc.CustomFields = make(CustomFields)

	err := jsonutil.UnmarshalWithCustomFields(data, alias, rc.CustomFields)
	if err != nil {
		return err
	}

	return nil
}

func ParseCredential(vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	
}

type credentialOpts struct {
	publicKeyFetcher      didsignjwt.PublicKeyFetcher
	disabledCustomSchema  bool
	schemaLoader          *CredentialSchemaLoader
	modelValidationMode   vcModelValidationMode
	allowedCustomContexts map[string]bool
	allowedCustomTypes    map[string]bool
	disableProofCheck     bool
	strictValidation      bool
	ldpSuites             []signatureapi.SignatureSuite
	defaultSchema         string
	disableValidation     bool
	verifyDataIntegrity   *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

type CredentialSchemaLoader struct {
	schemaDownloadClient *http.Client
	cache                SchemaCache
	jsonLoader           gojsonschema.JSONLoader
}

type SchemaCache interface {
	Put(k string, v []byte)
	Get(k string) ([]byte, bool)
}

type vcModelValidationMode int

type jsonldCredentialOpts struct {
	jsonldDocumentLoader jsonld.DocumentLoader
	externalContext      []string
	jsonldOnlyValidRDF   bool
}

type CredentialOpt func(opts *credentialOpts)

func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}
