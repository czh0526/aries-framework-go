package issuer

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/sdjwt/common"
	jsonutil "github.com/czh0526/aries-framework-go/component/models/util/json"
	"github.com/czh0526/aries-framework-go/component/models/util/maphelpers"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	mathrand "math/rand"
	"strings"
	"time"
)

const (
	defaultHash = crypto.SHA256

	decoyMinElements = 1
	decoyMaxElements = 4

	credentialSubjectKey = "credentialSubject"
	vcKey                = "vc"
)

var mr = mathrand.New(mathrand.NewSource(time.Now().Unix()))

type newOpts struct {
	Subject  string
	Audience string
	JTI      string
	ID       string

	Expiry    *josejwt.NumericDate
	NotBefore *josejwt.NumericDate
	IssuedAt  *josejwt.NumericDate

	HolderPublicKey *jwk.JWK
	HashAlg         crypto.Hash

	jsonMarshal func(v interface{}) ([]byte, error)
	getSalt     func() (string, error)

	addDecoyDigests bool
	version         common.SDJWTVersion

	structuredClaims  bool
	nonSDClaimsMap    map[string]bool
	alwaysInclude     map[string]bool
	recursiveClaimMap map[string]bool
}

type NewOpt func(opts *newOpts)

func WithSDJWTVersion(version common.SDJWTVersion) NewOpt {
	return func(opts *newOpts) {
		opts.version = version
	}
}

func WithStructuredClaims(flag bool) NewOpt {
	return func(opts *newOpts) {
		opts.structuredClaims = flag
	}
}

func WithRecursiveClaimsObject(recursiveClaimsObject []string) NewOpt {
	return func(opts *newOpts) {
		opts.recursiveClaimMap = common.SliceToMap(recursiveClaimsObject)
	}
}

func WithAlwaysIncludeObjects(alwaysIncludeObjects []string) NewOpt {
	return func(opts *newOpts) {
		opts.alwaysInclude = common.SliceToMap(alwaysIncludeObjects)
	}
}

func WithNonSelectivelyDisclosableClaims(nonSDClaims []string) NewOpt {
	return func(opts *newOpts) {
		opts.nonSDClaimsMap = common.SliceToMap(nonSDClaims)
	}
}

func WithHashAlgorithm(hashAlg crypto.Hash) NewOpt {
	return func(opts *newOpts) {
		opts.HashAlg = hashAlg
	}
}

func WithNotBefore(notBefore *josejwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.NotBefore = notBefore
	}
}

func WithIssuedAt(issuedAt *josejwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.IssuedAt = issuedAt
	}
}

func WithExpiry(expiry *josejwt.NumericDate) NewOpt {
	return func(opts *newOpts) {
		opts.Expiry = expiry
	}
}

func WithHolderPublicKey(jwk *jwk.JWK) NewOpt {
	return func(opts *newOpts) {
		opts.HolderPublicKey = jwk
	}
}

func WithSaltFunc(f func() (string, error)) NewOpt {
	return func(opts *newOpts) {
		opts.getSalt = f
	}
}

type SelectiveDisclosureJWT struct {
	SignedJWT   *modeljwt.JSONWebToken
	Disclosures []string
}

func NewFromVC(vc map[string]interface{}, headers jose.Headers,
	signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	nOpts := &newOpts{
		version: common.SDJWTVersionDefault,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	csObj, ok := common.GetKeyFromVC(credentialSubjectKey, vc)
	if !ok {
		return nil, fmt.Errorf("credential subject not found")
	}

	cs, ok := csObj.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("credential subject must be an object")
	}

	token, err := New("", cs, nil, &unsecuredJWTSigner{}, opts...)
	if err != nil {
		return nil, err
	}

	vcClaims, err := getBuilderByVersion(nOpts.version).ExtractCredentialClaims(vc)
	if err != nil {
		return nil, err
	}

	selectiveCredentialSubject := maphelpers.CopyMap(token.SignedJWT.Payload)

	vcClaims[common.SDAlgorithmKey] = selectiveCredentialSubject[common.SDAlgorithmKey]
	delete(selectiveCredentialSubject, common.SDAlgorithmKey)

	cnfObj, ok := selectiveCredentialSubject[common.CNFKey]
	if ok {
		vcClaims[common.CNFKey] = cnfObj
		delete(selectiveCredentialSubject, common.CNFKey)
	}

	vcClaims[credentialSubjectKey] = selectiveCredentialSubject

	signedJWT, err := modeljwt.NewSigned(vc, headers, signer)
	if err != nil {
		return nil, err
	}

	sdJWT := &SelectiveDisclosureJWT{
		Disclosures: token.Disclosures,
		SignedJWT:   signedJWT,
	}

	return sdJWT, nil
}

func New(issuer string, claims interface{}, headers jose.Headers,
	signer jose.Signer, opts ...NewOpt) (*SelectiveDisclosureJWT, error) {
	nOpts := &newOpts{
		jsonMarshal:    json.Marshal,
		HashAlg:        defaultHash,
		nonSDClaimsMap: make(map[string]bool),
		version:        common.SDJWTVersionDefault,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	claimsMap, err := modeljwt.PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("convert payload to map: %w", err)
	}

	// 递归检查 Key("_sd") 是否存在 claimsMap 中
	found := common.KeyExistsInMap(common.SDKey, claimsMap)
	if found {
		return nil, fmt.Errorf("key `%s` cannot be present in the claims", common.SDKey)
	}

	// 构造 SD-JWT Builder
	sdJWTBuilder := getBuilderByVersion(nOpts.version)
	if nOpts.getSalt == nil {
		nOpts.getSalt = sdJWTBuilder.GenerateSalt
	}

	// 构造 DisclosureEntities，以及每个 DisclosureEntity 的 digest
	disclosures, digests, err := sdJWTBuilder.CreateDisclosuresAndDigests("", claimsMap, nOpts)
	if err != nil {
		return nil, err
	}

	// 构造 payload
	payload, err := jsonutil.MergeCustomFields(createPayload(issuer, nOpts), digests)
	if err != nil {
		return nil, fmt.Errorf("failed to merge payload and digests: %w", err)
	}

	// 构造 JWS
	signedJWT, err := modeljwt.NewSigned(payload, headers, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT from payload[%+v]: %w", payload, err)
	}

	var disArr []string
	for _, d := range disclosures {
		disArr = append(disArr, d.Result)
	}

	return &SelectiveDisclosureJWT{
		Disclosures: disArr,
		SignedJWT:   signedJWT,
	}, nil
}

func (j *SelectiveDisclosureJWT) Serialize(detached bool) (string, error) {
	if j.SignedJWT == nil {
		return "", errors.New("JWS serialization is supported only")
	}

	signedJWT, err := j.SignedJWT.Serialize(detached)
	if err != nil {
		return "", err
	}

	cf := common.CombinedFormatForIssuance{
		SDJWT:       signedJWT,
		Disclosures: j.Disclosures,
	}

	return cf.Serialize(), nil
}

func (j *SelectiveDisclosureJWT) DecodeClaims(c interface{}) error {
	return j.SignedJWT.DecodeClaims(c)
}

type payload struct {
	Issuer    string               `json:"iss,omitempty"`
	Subject   string               `json:"sub,omitempty"`
	Audience  string               `json:"aud,omitempty"`
	JTI       string               `json:"jti,omitempty"`
	Expiry    *josejwt.NumericDate `json:"exp,omitempty"`
	NotBefore *josejwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *josejwt.NumericDate `json:"iat,omitempty"`
	ID        string               `json:"id,omitempty"`

	// SD-JWT 相关
	CNF   map[string]interface{} `json:"cnf,omitempty"`
	SDAlg string                 `json:"_sd_alg,omitempty"`
}

func createPayload(issuer string, nOpts *newOpts) *payload {
	var cnf map[string]interface{}
	if nOpts.HolderPublicKey != nil {
		cnf = make(map[string]interface{})
		cnf["jwk"] = nOpts.HolderPublicKey
	}

	payload := &payload{
		Issuer:    issuer,
		JTI:       nOpts.JTI,
		ID:        nOpts.ID,
		Subject:   nOpts.Subject,
		Audience:  nOpts.Audience,
		IssuedAt:  nOpts.IssuedAt,
		Expiry:    nOpts.Expiry,
		NotBefore: nOpts.NotBefore,
		CNF:       cnf,
		SDAlg:     strings.ToLower(nOpts.HashAlg.String()),
	}

	return payload
}

// createDecoyDisclosures 创建随机数量的 DisclosureEntity 用于混淆
func createDecoyDisclosures(opts *newOpts) ([]*DisclosureEntity, error) {
	if !opts.addDecoyDigests {
		return nil, nil
	}

	n := mr.Intn(decoyMaxElements-decoyMinElements+1) + decoyMinElements

	var decoyDisclosures []*DisclosureEntity

	for i := 0; i < n; i++ {
		salt, err := opts.getSalt()
		if err != nil {
			return nil, err
		}

		decoyDisclosures = append(decoyDisclosures, &DisclosureEntity{
			Result: salt,
			Salt:   salt,
		})
	}

	return decoyDisclosures, nil
}

func createDigests(disclosures []*DisclosureEntity, nOpts *newOpts) ([]string, error) {
	var digests []string

	for _, disclosure := range disclosures {
		digest, inErr := createDigest(disclosure, nOpts)
		if inErr != nil {
			return nil, fmt.Errorf("hash disclosure: %w", inErr)
		}

		digests = append(digests, digest)
	}

	mr.Shuffle(len(digests), func(i, j int) {
		digests[i], digests[j] = digests[j], digests[i]
	})
	return digests, nil
}

func createDigest(disclosure *DisclosureEntity, nOpts *newOpts) (string, error) {
	digest, inErr := common.GetHash(nOpts.HashAlg, disclosure.Result)
	if inErr != nil {
		return "", fmt.Errorf("hash disclosure: %w", inErr)
	}

	disclosure.DebugDigest = digest

	return digest, nil
}

func generateSalt(sizeBytes int) (string, error) {
	salt := make([]byte, sizeBytes)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// it is RECOMMENDED to base64url-encode the salt value, producing a string.
	return base64.RawURLEncoding.EncodeToString(salt), nil
}

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() jose.Headers {
	return map[string]interface{}{
		jose.HeaderAlgorithm: modeljwt.AlgorithmNone,
	}
}
