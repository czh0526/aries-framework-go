package issuer

import (
	"errors"
	"fmt"
	"reflect"
)

type DisclosureEntity struct {
	Result      string
	Salt        string
	Key         string
	Value       interface{}
	DebugArr    []interface{} `json:"-"`
	DebugStr    string
	DebugDigest string
}

type SDJWTBuilderV5 struct {
	debugMode bool
	saltSize  int
}

func (s *SDJWTBuilderV5) CreateDisclosuresAndDigests(
	path string,
	claims map[string]interface{},
	opts *newOpts) ([]*DisclosureEntity, map[string]interface{}, error) {

	return s.createDisclosuresAndDigestsInternal(path, claims, opts, false)
}

func (s *SDJWTBuilderV5) ExtractCredentialClaims(vcClaims map[string]interface{}) (map[string]interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (s *SDJWTBuilderV5) GenerateSalt() (string, error) {
	//TODO implement me
	panic("implement me")
}

var _ builder = (*SDJWTBuilderV5)(nil)

func (s *SDJWTBuilderV5) createDisclosuresAndDigestsInternal(
	path string,
	claims map[string]interface{},
	opts *newOpts,
	ignorePrimitives bool) ([]*DisclosureEntity, map[string]interface{}, error) {
	digestsMap := map[string]interface{}{}
	finalSDDigest, err := createDecoyDisclosures(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create decoy disclosures: %w", err)
	}

	var allDisclosures []*DisclosureEntity

	for key, value := range claims {
		curPath := key
		if path != "" {
			curPath = path + "." + key
		}

		kind := reflect.TypeOf(value).Kind()
		valOption := s.extractCredentialClaims(curPath, opts)

		switch kind {
		case reflect.Map:
		case reflect.Array:
		case reflect.Slice:
		default:
			if valOption.IsIgnored || ignorePrimitives {
				digestsMap[key] = value
				continue
			}
		}
	}
}

func (s *SDJWTBuilderV5) createDisclosure(
	key string,
	value interface{},
	opts *newOpts) (*DisclosureEntity, error) {
	if opts.getSalt == nil {
		return nil, errors.New("missing Salt function")
	}

	salt, err := opts.getSalt()

}

func (s *SDJWTBuilderV5) extractCredentialClaims(curPath string, opts *newOpts) valueOption {
	return valueOption{
		IsStructured:    opts.structuredClaims,
		IsAlwaysInclude: s.isAlwaysInclude(curPath, opts),
		IsIgnored:       s.isIgnored(curPath, opts),
		IsRecursive:     s.isRecursive(curPath, opts),
	}
}

func (s *SDJWTBuilderV5) isAlwaysInclude(path string, opts *newOpts) bool {
	if opts == nil || len(opts.alwaysInclude) == 0 {
		return false
	}

	_, ok := opts.alwaysInclude[path]
	return ok
}

func (s *SDJWTBuilderV5) isIgnored(curPath string, opts *newOpts) bool {
	if opts == nil || len(opts.nonSDClaimsMap) == 0 {
		return false
	}

	_, ok := opts.nonSDClaimsMap[curPath]
	return ok
}

func (s *SDJWTBuilderV5) isRecursive(curPath string, opts *newOpts) bool {
	if opts == nil || len(opts.recursiveClaimMap) == 0 {
		return false
	}

	_, ok := opts.recursiveClaimMap[curPath]
	return ok
}

func NewSDJWTBuilderV5() *SDJWTBuilderV5 {
	return &SDJWTBuilderV5{
		saltSize: 128 / 8,
	}
}

type valueOption struct {
	IsStructured    bool
	IsAlwaysInclude bool
	IsIgnored       bool
	IsRecursive     bool
}
