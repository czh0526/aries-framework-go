package common

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
)

type SDJWTVersion int

const (
	CombinedFormatSeparator = "~"

	SDAlgorithmKey        = "_sd_alg"
	SDKey                 = "_sd"
	CNFKey                = "cnf"
	ArrayElementDigestKey = "..."
)

const (
	SDJWTVersionDefault = SDJWTVersionV2
	SDJWTVersionV2      = SDJWTVersion(2)
	SDJWTVersionV5      = SDJWTVersion(5)
)

type DisclosureClaimType int

const (
	disclosureElementsAmountForArrayDigest = 2
	disclosureElementsAmountForSDDigest    = 3

	saltPosition             = 0
	arrayDigestValuePosition = 1
	sdDigestNamePosition     = 1
	sdDigestValuePosition    = 2
)

const (
	DisclosureClaimTypeUnknown      = DisclosureClaimType(0)
	DisclosureClaimTypeArrayElement = DisclosureClaimType(2)
	DisclosureClaimTypeObject       = DisclosureClaimType(3)
	DisclosureClaimTypePlainText    = DisclosureClaimType(4)
)

type DisclosureClaim struct {
	Digest        string
	Disclosure    string
	Salt          string
	Elements      int
	Type          DisclosureClaimType
	Version       SDJWTVersion
	Name          string
	Value         interface{}
	IsValueParsed bool
}

type CombinedFormatForIssuance struct {
	SDJWT       string
	Disclosures []string
}

type CombineFormatForPresentation struct {
	SDJWT              string
	Disclosures        []string
	HolderVerification string
}

func ParseCombinedFormatForIssuance(combinedFormatForIssuance string) *CombinedFormatForIssuance {
	parts := strings.Split(combinedFormatForIssuance, CombinedFormatSeparator)

	var disclosures []string
	if len(parts) > 1 {
		disclosures = parts[1:]
	}

	sdJWT := parts[0]

	return &CombinedFormatForIssuance{
		SDJWT:       sdJWT,
		Disclosures: disclosures,
	}
}

func ParseCombinedFormatForPresentation(combineFormatForPresentation string) *CombineFormatForPresentation {
	parts := strings.Split(combineFormatForPresentation, CombinedFormatSeparator)

	var disclosures []string
	if len(parts) > 2 {
		disclosures = parts[1 : len(parts)-1]
	}

	var holderBinding string
	if len(parts) > 1 {
		holderBinding = parts[len(parts)-1]
	}

	sdJWT := parts[0]

	return &CombineFormatForPresentation{
		SDJWT:              sdJWT,
		Disclosures:        disclosures,
		HolderVerification: holderBinding,
	}
}

func GetCryptoHash(sdAlg string) (crypto.Hash, error) {
	var (
		cryptoHash crypto.Hash
		err        error
	)

	switch strings.ToUpper(sdAlg) {
	case crypto.SHA256.String():
		cryptoHash = crypto.SHA256
	case crypto.SHA384.String():
		cryptoHash = crypto.SHA384
	case crypto.SHA512.String():
		cryptoHash = crypto.SHA512
	default:
		err = fmt.Errorf("%s `%s` not unsupported", SDAlgorithmKey, sdAlg)
	}

	return cryptoHash, err
}

func GetCryptoHashFromClaims(claims map[string]interface{}) (crypto.Hash, error) {
	var cryptoHash crypto.Hash

	sdAlg, err := GetSDAlg(claims)
	if err != nil {
		return cryptoHash, err
	}

	return GetCryptoHash(sdAlg)
}

func GetSDAlg(claims map[string]interface{}) (string, error) {
	var alg string

	obj, ok := claims[SDAlgorithmKey]
	if !ok {
		obj, ok = GetKeyFromVC(SDAlgorithmKey, claims)
		if !ok {
			return "", fmt.Errorf("%s must be present in SD-JWT", SDAlgorithmKey)
		}
	}

	alg, ok = obj.(string)
	if !ok {
		return "", fmt.Errorf("%s must be pa string", SDAlgorithmKey)
	}

	return alg, nil
}

func GetKeyFromVC(key string, claims map[string]interface{}) (interface{}, bool) {
	if obj, ok := claims[key]; ok {
		return obj, true
	}

	vcObj, ok := claims["vc"]
	if !ok {
		return nil, false
	}

	vc, ok := vcObj.(map[string]interface{})
	if !ok {
		return nil, false
	}

	obj, ok := vc[key]
	if !ok {
		return nil, false
	}

	return obj, true
}

func GetDisclosureClaims(disclosures []string, hash crypto.Hash) ([]*DisclosureClaim, error) {
	disclosureClaims, err := getDisclosureClaims(disclosures, hash)
	if err != nil {
		return nil, err
	}

	recData := &recursiveData{
		disclosures:          disclosureClaims,
		cleanupDigestsClaims: true,
	}

	for _, wrappedDisclosureClaim := range disclosureClaims {
		if err = setDisclosureClaimValue(recData, wrappedDisclosureClaim); err != nil {
			return nil, err
		}
	}

	final := make([]*DisclosureClaim, 0, len(disclosureClaims))
	for _, disclosureClaim := range recData.disclosures {
		final = append(final, disclosureClaim)
	}

	return final, nil
}

func GetHash(hash crypto.Hash, value string) (string, error) {
	if !hash.Available() {
		return "", fmt.Errorf("hash function not available for: %d", hash)
	}

	hasher := hash.New()
	if _, hashErr := hasher.Write([]byte(value)); hashErr != nil {
		return "", hashErr
	}
	result := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(result), nil
}

func KeyExistsInMap(key string, m map[string]interface{}) bool {
	for k, v := range m {
		if k == key {
			return true
		}

		if obj, ok := v.(map[string]interface{}); ok {
			exists := KeyExistsInMap(key, obj)
			if exists {
				return true
			}
		}
	}

	return false
}

func SliceToMap(ids []string) map[string]bool {
	values := make(map[string]bool)
	for _, id := range ids {
		values[id] = true
	}

	return values
}

func getMap(value interface{}) (map[string]interface{}, bool) {
	val, ok := value.(map[string]interface{})

	return val, ok
}

func stringArray(entry interface{}) ([]string, error) {
	if entry == nil {
		return nil, nil
	}

	sliceValue := reflect.ValueOf(entry)
	if sliceValue.Kind() != reflect.Slice {
		return nil, fmt.Errorf("entry type[%T] is not an array", entry)
	}

	// Iterate over the slice and convert each element to a string
	stringSlice := make([]string, sliceValue.Len())

	for i := 0; i < sliceValue.Len(); i++ {
		sliceVal := sliceValue.Index(i).Interface()
		val, ok := sliceVal.(string)

		if !ok {
			return nil, fmt.Errorf("entry item type[%T] is not a string", sliceVal)
		}

		stringSlice[i] = val
	}

	return stringSlice, nil
}

type CombinedFormatForPresentation struct {
	SDJWT              string
	Disclosures        []string
	HolderVerification string
}

func (cf *CombinedFormatForPresentation) Serialize() string {
	presentation := cf.SDJWT
	for _, disclosure := range cf.Disclosures {
		presentation += CombinedFormatSeparator + disclosure
	}

	if len(cf.Disclosures) > 0 || cf.HolderVerification != "" {
		presentation += CombinedFormatSeparator
	}

	presentation += cf.HolderVerification

	return presentation
}
