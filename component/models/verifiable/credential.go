package verifiable

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	sigapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"
	"net/http"
	"reflect"
	"strings"
)

type vcModelValidationMode int

const (
	combinedValidation vcModelValidationMode = iota
	jsonldValidation
	baseContextValidation
	baseContextExtendedValidation
)

const (
	schemaPropertyType              = "type"
	schemaPropertyCredentialSubject = "credentialSubject"
	schemaPropertyIssuer            = "issuer"
	schemaPropertyIssuanceDate      = "issuanceDate"
)

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

func (vc *Credential) UnmarshalJSON(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}

func (vc *Credential) MarshalJSON() ([]byte, error) {
	if vc.JWT != "" {
		if vc.SDJWTHashAlg != "" {
			sdJWT, err := vc.MarshalWithDisclosure(DiscloseAll())
			if err != nil {
				return nil, err
			}

			return []byte("\"" + sdJWT + "\""), nil
		}

		return []byte("\"" + vc.JWT + "\""), nil
	}

	raw, err := vc.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	return byteCred, nil
}

func (vc *Credential) JWTClaims(minimizeVC bool) (*JWTCredClaims, error) {
	return newJWTCredClaims(vc, minimizeVC)
}

func (vc *Credential) raw() (*rawCredential, error) {
	rawRefreshService, err := typedIDToRaw(vc.RefreshService)
	if err != nil {
		return nil, err
	}

	rawTermsOfUse, err := typedIDToRaw(vc.TermsOfUse)
	if err != nil {
		return nil, err
	}

	proof, err := proofsToRaw(vc.Proofs)
	if err != nil {
		return nil, err
	}

	var schema interface{}
	if len(vc.Schemas) > 0 {
		schema = vc.Schemas
	}

	issuer, err := issuerToRaw(vc.Issuer)
	if err != nil {
		return nil, err
	}

	subject, err := subjectToBytes(vc.Subject)
	if err != nil {
		return nil, err
	}

	r := &rawCredential{
		Context:        contextToRaw(vc.Context, vc.CustomContext),
		ID:             vc.ID,
		Type:           typesToRaw(vc.Types),
		Subject:        subject,
		Proof:          proof,
		Status:         vc.Status,
		Issuer:         issuer,
		Schema:         schema,
		Evidence:       vc.Evidence,
		RefreshService: rawRefreshService,
		TermsOfUse:     rawTermsOfUse,
		Issued:         vc.Issued,
		Expired:        vc.Expired,
		JWT:            vc.JWT,
		SDJWTHashAlg:   vc.SDJWTHashAlg,
		CustomFields:   vc.CustomFields,
	}

	return r, nil
}

func contextToRaw(context []string, customContext []interface{}) interface{} {
	if len(customContext) > 0 {
		sContext := make([]interface{}, len(context), len(context)+len(customContext))

		for i := range context {
			sContext[i] = context[i]
		}

		sContext = append(sContext, customContext...)
		return sContext
	}

	return context
}

func typedIDToRaw(typedIDs []TypedID) ([]byte, error) {
	switch len(typedIDs) {
	case 0:
		return nil, nil
	case 1:
		return json.Marshal(typedIDs[0])
	default:
		return json.Marshal(typedIDs)
	}
}

func proofsToRaw(proofs []Proof) ([]byte, error) {
	switch len(proofs) {
	case 0:
		return nil, nil
	case 1:
		return json.Marshal(proofs[0])
	default:
		return json.Marshal(proofs)
	}
}

func issuerToRaw(issuer Issuer) (json.RawMessage, error) {
	return issuer.MarshalJSON()
}

func typesToRaw(types []string) interface{} {
	if len(types) == 1 {
		return types[0]
	}

	return types
}

func subjectToBytes(subject interface{}) ([]byte, error) {
	if subject == nil {
		return nil, nil
	}

	switch s := subject.(type) {
	case string:
		return json.Marshal(s)

	case []map[string]interface{}:
		if len(s) == 1 {
			return json.Marshal(s[0])
		}
		return json.Marshal(s)

	case map[string]interface{}:
		return subjectMapToRaw(s)

	case Subject:
		return s.MarshalJSON()

	case []Subject:
		if len(s) == 1 {
			return s[0].MarshalJSON()
		}
		return json.Marshal(s)

	default:
		return subjectStructToRaw(subject)
	}
}

func subjectMapToRaw(subject map[string]interface{}) (json.RawMessage, error) {
	if len(subject) == 1 {
		if _, ok := subject["id"]; ok {
			return json.Marshal(safeStringValue(subject["id"]))
		}
	}
	return json.Marshal(subject)
}

func subjectStructToRaw(subject interface{}) (json.RawMessage, error) {
	if reflect.TypeOf(subject).Kind() == reflect.Slice {
		sValue := reflect.ValueOf(subject)
		subjects := make([]interface{}, sValue.Len())

		for i := 0; i < sValue.Len(); i++ {
			subjects[i] = sValue.Index(i).Interface()
		}
	}

	sMap, err := jsonutil.ToMap(subject)
	if err != nil {
		return nil, errors.New("subject of unknown structure")
	}

	return subjectToBytes(sMap)
}

var _ json.Marshaler = (*Credential)(nil)
var _ json.Unmarshaler = (*Credential)(nil)

type rawCredential struct {
	Context          interface{}           `json:"@context,omitempty"`
	ID               string                `json:"id,omitempty"`
	Type             interface{}           `json:"type,omitempty"`
	Subject          json.RawMessage       `json:"credentialSubject,omitempty"`
	Issued           *timeutil.TimeWrapper `json:"issuanceDate,omitempty"`
	Expired          *timeutil.TimeWrapper `json:"expirationDate,omitempty"`
	Proof            json.RawMessage       `json:"proof,omitempty"`
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

func newCredential(raw *rawCredential) (*Credential, error) {
	var schemas []TypedID

	if raw.Schema != nil {
		var err error
		schemas, err = decodeCredentialSchemas(raw)
		if err != nil {
			return nil, fmt.Errorf("fill credential schemas from raw: %w", err)
		}
	} else {
		schemas = make([]TypedID, 0)
	}

	types, err := decodeType(raw.Type)
	if err != nil {
		return nil, fmt.Errorf("fill credential types from raw: %w", err)
	}

	issuer, err := parseIssuer(raw.Issuer)
	if err != nil {
		return nil, fmt.Errorf("fill credential issuer from raw: %w", err)
	}

	context, customContext, err := decodeContext(raw.Context)
	if err != nil {
		return nil, fmt.Errorf("fill credential context from raw: %w", err)
	}

	termsOfUse, err := parseTypedID(raw.TermsOfUse)
	if err != nil {
		return nil, fmt.Errorf("fill credential terms of use from raw: %w", err)
	}

	refreshService, err := parseTypedID(raw.RefreshService)
	if err != nil {
		return nil, fmt.Errorf("fill credential refresh service from raw: %w", err)
	}

	proofs, err := parseProof(raw.Proof)
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	subjects, err := parseSubject(raw.Subject)
	if err != nil {
		return nil, fmt.Errorf("fill credential subject from raw: %w", err)
	}

	alg, _ := common.GetCryptoHash(raw.SDJWTHashAlg)
	if alg == 0 {
		sub, _ := subjects.([]Subject)
		if len(sub) > 0 && len(sub[0].CustomFields) > 0 {
			alg, _ = common.GetCryptoHashFromClaims(sub[0].CustomFields)
		}
	}

	disclosures, err := parseDisclosures(raw.SDJWTDisclosures, alg)
	if err != nil {
		return nil, fmt.Errorf("fill credential sdjwt disclosures from raw: %w", err)
	}

	return &Credential{
		Context:          context,
		CustomContext:    customContext,
		ID:               raw.ID,
		Types:            types,
		Subject:          subjects,
		Issuer:           issuer,
		Issued:           raw.Issued,
		Expired:          raw.Expired,
		Proofs:           proofs,
		Status:           raw.Status,
		Schemas:          schemas,
		Evidence:         raw.Evidence,
		TermsOfUse:       termsOfUse,
		RefreshService:   refreshService,
		JWT:              raw.JWT,
		CustomFields:     raw.CustomFields,
		SDJWTHashAlg:     raw.SDJWTHashAlg,
		SDJWTVersion:     raw.SDJWTVersion,
		SDJWTDisclosures: disclosures,
	}, nil
}

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

type CustomCredentialProducer interface {
	Accept(vc *Credential) bool

	Apply(vc *Credential, dataJSON []byte) (interface{}, error)
}

func ParseCredential(vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	vcOpts := getCredentialOpts(opts)

	vcStr := unwrapStringVC(vcData)

	var (
		vcDataDecoded []byte
		externalJWT   string
		err           error
		isJWT         bool
		disclosures   []string
		holderBinding string
		sdJWTVersion  common.SDJWTVersion
	)

	isJWT, vcStr, disclosures, holderBinding = isJWTVC(vcStr)
	if isJWT {
		_, vcDataDecoded, err = decodeJWTVC(vcStr, vcOpts)
		if err != nil {
			return nil, fmt.Errorf("decode new JWT credential: %w", err)
		}

		if err = validateDisclosures(vcDataDecoded, disclosures); err != nil {
			return nil, err
		}

		externalJWT = vcStr

	} else {
		vcDataDecoded, err = decodeLDVC(vcData, vcStr, vcOpts)
		if err != nil {
			return nil, fmt.Errorf("decode new credential: %w", err)
		}
	}

	vc, err := populateCredential(vcDataDecoded, disclosures, sdJWTVersion)
	if err != nil {
		return nil, err
	}

	if externalJWT == "" && !vcOpts.disableValidation {
		err = validateCredential(vc, vcDataDecoded, vcOpts)
		if err != nil {
			return nil, err
		}
	}

	vc.JWT = externalJWT
	vc.SDHolderBinding = holderBinding

	return vc, nil
}

func populateCredential(vcJSON []byte, sdDisclosures []string, sdJWTVersion common.SDJWTVersion) (*Credential, error) {
	var raw rawCredential

	err := json.Unmarshal(vcJSON, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal new credential: %w", err)
	}

	raw.SDJWTDisclosures = sdDisclosures
	raw.SDJWTVersion = sdJWTVersion

	vc, err := newCredential(&raw)
	if err != nil {
		return nil, fmt.Errorf("build new credential: %w", err)
	}

	return vc, nil
}

func decodeCredentialSchemas(data *rawCredential) ([]TypedID, error) {
	switch schema := data.Schema.(type) {
	case []interface{}:
		tids := make([]TypedID, len(schema))
		for i := range schema {
			tid, err := newTypedID(schema[i])
			if err != nil {
				return nil, err
			}

			tids[i] = tid
		}
		return tids, nil

	case interface{}:
		tid, err := newTypedID(schema)
		if err != nil {
			return nil, err
		}

		return []TypedID{tid}, nil

	default:
		return nil, errors.New("verifiable credential schema of unsupported format")
	}
}

func parseTypedID(data json.RawMessage) ([]TypedID, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var singleTypedID TypedID

	err := json.Unmarshal(data, &singleTypedID)
	if err == nil {
		return []TypedID{singleTypedID}, nil
	}

	var composedTypedID []TypedID
	err = json.Unmarshal(data, &composedTypedID)
	if err == nil {
		return composedTypedID, nil
	}

	return nil, err
}

func parseSubject(subjectBytes json.RawMessage) (interface{}, error) {
	if len(subjectBytes) == 0 {
		return nil, nil
	}

	var subjectID string
	err := json.Unmarshal(subjectBytes, &subjectID)
	if err == nil {
		return subjectID, nil
	}

	var subject Subject
	err = json.Unmarshal(subjectBytes, &subject)
	if err == nil {
		return subject, nil
	}

	var subjects []Subject
	err = json.Unmarshal(subjectBytes, &subjects)
	if err == nil {
		return subjects, nil
	}

	return nil, fmt.Errorf("verifiable credential subject of unsupported format")
}

func parseDisclosures(disclosures []string, hash crypto.Hash) ([]*common.DisclosureClaim, error) {
	if len(disclosures) == 0 {
		return nil, nil
	}

	disc, err := common.GetDisclosureClaims(disclosures, hash)
	if err != nil {
		return nil, fmt.Errorf("parsing disclosures from SD-JWT credential: %w", err)
	}

	return disc, nil
}

func getCredentialOpts(opts []CredentialOpt) *credentialOpts {
	crOpts := &credentialOpts{
		modelValidationMode: combinedValidation,
		verifyDataIntegrity: &verifyDataIntegrityOpts{},
	}

	for _, opt := range opts {
		opt(crOpts)
	}

	if crOpts.schemaLoader == nil {
		crOpts.schemaLoader = newDefaultSchemaLoader()
	}

	return crOpts
}

type externalJWTVC struct {
	JWT string `json:"jwt,omitempty"`
}

func unQuote(s []byte) []byte {
	if len(s) <= 1 {
		return s
	}

	if s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}

	return s
}

func unwrapStringVC(vcData []byte) string {
	vcStr := string(unQuote(vcData))

	jwtHolder := &externalJWTVC{}
	e := json.Unmarshal(vcData, jwtHolder)

	hasJWT := e == nil && jwtHolder.JWT != ""
	if hasJWT {
		vcStr = jwtHolder.JWT
	}

	return vcStr
}

func newDefaultSchemaLoader() *CredentialSchemaLoader {
	return &CredentialSchemaLoader{
		schemaDownloadClient: &http.Client{},
		jsonLoader:           defaultSchemaLoader(),
	}
}

func defaultSchemaLoader() gojsonschema.JSONLoader {
	return gojsonschema.NewStringLoader(JSONSchemaLoader())
}

type schemaOpts struct {
	disableChecks []string
}

type SchemaOpt func(*schemaOpts)

func WithDisableRequiredField(fieldName string) SchemaOpt {
	return func(opts *schemaOpts) {
		opts.disableChecks = append(opts.disableChecks, fieldName)
	}
}

// DefaultSchemaTemplate describes default schema.
const DefaultSchemaTemplate = `{
  "required": [
    "@context"
    %s    
  ],
  "properties": {
    "@context": {
      "anyOf": [
        {
          "type": "string",
          "const": "https://www.w3.org/2018/credentials/v1"
        },
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/2018/credentials/v1"
            }
          ],
          "uniqueItems": true,
          "additionalItems": {
            "anyOf": [
              {
                "type": "object"
              },
              {
                "type": "string"
              }
            ]
          }
        }
      ]
    },
    "id": {
      "type": "string"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "minItems": 1,
          "contains": {
            "type": "string",
            "pattern": "^VerifiableCredential$"
          }
        },
        {
          "type": "string",
          "pattern": "^VerifiableCredential$"
        }
      ]
    },
    "credentialSubject": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        }
      ]
    },
    "issuer": {
      "anyOf": [
        {
          "type": "string",
          "format": "uri"
        },
        {
          "type": "object",
          "required": [
            "id"
          ],
          "properties": {
            "id": {
              "type": "string",
              "format": "uri"
            }
          }
        }
      ]
    },
    "issuanceDate": {
      "type": "string",
      "format": "date-time"
    },
    "proof": {
      "anyOf": [
        {
          "$ref": "#/definitions/proof"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/proof"
          }
        },
        {
          "type": "null"
        }
      ]
    },
    "expirationDate": {
      "type": [
        "string",
        "null"
      ],
      "format": "date-time"
    },
    "credentialStatus": {
      "$ref": "#/definitions/typedID"
    },
    "credentialSchema": {
      "$ref": "#/definitions/typedIDs"
    },
    "evidence": {
      "$ref": "#/definitions/typedIDs"
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "anyOf": [
        {
          "type": "null"
        },
        {
          "type": "object",
          "required": [
            "id",
            "type"
          ],
          "properties": {
            "id": {
              "type": "string",
              "format": "uri"
            },
            "type": {
              "anyOf": [
                {
                  "type": "string"
                },
                {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                }
              ]
            }
          }
        }
      ]
    },
    "typedIDs": {
      "anyOf": [
        {
          "$ref": "#/definitions/typedID"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/typedID"
          }
        },
        {
          "type": "null"
        }
      ]
    },
    "proof": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string"
        }
      }
    }
  }
}
`

func JSONSchemaLoader(opts ...SchemaOpt) string {
	defaultRequired := []string{
		schemaPropertyType,
		schemaPropertyCredentialSubject,
		schemaPropertyIssuer,
		schemaPropertyIssuanceDate,
	}

	dsOpts := &schemaOpts{}
	for _, opt := range opts {
		opt(dsOpts)
	}

	required := ""
	for _, prop := range defaultRequired {
		filterOut := false

		for _, d := range dsOpts.disableChecks {
			if prop == d {
				filterOut = true
				break
			}
		}

		if !filterOut {
			required += fmt.Sprintf(" ,%q", prop)
		}
	}

	return fmt.Sprintf(DefaultSchemaTemplate, required)
}

type credentialOpts struct {
	publicKeyFetcher      didsignjwt.PublicKeyFetcher
	disabledCustomSchema  bool
	schemaLoader          *CredentialSchemaLoader
	modelValidationMode   vcModelValidationMode
	allowedCustomContexts map[string]bool
	allowedCustomTypes    map[string]bool
	disabledProofCheck    bool
	strictValidation      bool
	ldpSuites             []sigapi.SignatureSuite
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

func isJWTVC(vcStr string) (bool, string, []string, string) {
	var (
		disclosures   []string
		holderBinding string
	)

	tmpVCStr := vcStr
	if strings.Contains(tmpVCStr, common.CombinedFormatSeparator) {
		sdTokens := strings.Split(vcStr, common.CombinedFormatSeparator)
		lastElem := sdTokens[len(sdTokens)-1]

		isPresentation := lastElem == "" || jwt.IsJWS(lastElem)
		if isPresentation {
			cffp := common.ParseCombinedFormatForPresentation(vcStr)

			disclosures = cffp.Disclosures
			tmpVCStr = cffp.SDJWT
			holderBinding = cffp.HolderVerification

		} else {
			cffi := common.ParseCombinedFormatForIssuance(vcStr)

			disclosures = cffi.Disclosures
			tmpVCStr = cffi.SDJWT
		}
	}

	if jwt.IsJWS(tmpVCStr) {
		return true, tmpVCStr, disclosures, holderBinding
	}

	return false, vcStr, nil, ""
}

func decodeJWTVC(vcStr string, vcOpts *credentialOpts) (jose.Headers, []byte, error) {
	if vcOpts.publicKeyFetcher == nil && !vcOpts.disabledProofCheck {
		return nil, nil, errors.New("public key fetcher is not defined")
	}

	joseHeaders, vcDecodedBytes, err := decodeCredJWS(vcStr, !vcOpts.disabledProofCheck, vcOpts.publicKeyFetcher)
	if err != nil {
		return nil, nil, fmt.Errorf("JWS decoding: %w", err)
	}

	return joseHeaders, vcDecodedBytes, nil
}

func decodeLDVC(vcData []byte, vcStr string, vcOpts *credentialOpts) ([]byte, error) {
	if jwt.IsJWTUnsecured(vcStr) {
		var e error
		vcData, e = decodeCredJWTUnsecured(vcStr)
		if e != nil {
			return nil, fmt.Errorf("unsecured JWT decoding: %w", e)
		}
	}
	return vcData, checkEmbeddedProof(vcData, getEmbeddedProofCheckOpts(vcOpts))
}

func validateDisclosures(vcBytes []byte, disclosures []string) error {
	return fmt.Errorf("not implemented")
}

func validateCredential(vc *Credential, vcBytes []byte, vcOpts *credentialOpts) error {
	return fmt.Errorf("not implemented")
}
