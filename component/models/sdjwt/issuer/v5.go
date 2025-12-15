package issuer

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

	return s.createDisclosuresAndDigestsInternal()
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

func NewSDJWTBuilderV5() *SDJWTBuilderV5 {
	return &SDJWTBuilderV5{
		saltSize: 128 / 8,
	}
}
