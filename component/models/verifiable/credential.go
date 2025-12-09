package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/jwt/didsignjwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	signatureapi "github.com/czh0526/aries-framework-go/component/models/signature/api"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
	timeutil "github.com/czh0526/aries-framework-go/component/models/util/time"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"
	"net/http"
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

	isJWT, vcStr, disclosures, holderBinding := isJWTVC(vcStr)
	if isJWT {
		_, vcDataDecoded, err = decodeJWTVC(vcStr, vcOpts)
	} else {
		vcDataDecoded, err = decodeLDVC(vcData, vcStr, vcOpts)
	}
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
	if vcOpts.publicKeyFetcher == nil && !vcOpts.disableProofCheck {
		return nil, nil, errors.New("public key fetcher is not defined")
	}

	joseHeaders, vcDecodedBytes, err := decodeCredJWS(vcStr, !vcOpts.disableProofCheck, vcOpts.publicKeyFetcher)
	if err != nil {
		return nil, nil, fmt.Errorf("JWS decoding: %w", err)
	}

	return joseHeaders, vcDecodedBytes, nil
}
