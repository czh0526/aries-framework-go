package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	docjose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"reflect"
	"strings"
)

const (
	TypeJWT       = "JWT"
	TypeSDJWT     = "SD-JWT"
	AlgorithmNone = "none"
)

type parseOpts struct {
	detachedPayload         []byte
	sigVerifier             docjose.SignatureVerifier
	ignoreClaimsMapDecoding bool
}

type ParseOpt func(opts *parseOpts)

func WithJWTDetachedPayload(payload []byte) ParseOpt {
	return func(opts *parseOpts) {
		opts.detachedPayload = payload
	}
}

func WithIgnoreClaimsMapDecoding(ignoreClaimsMapDecoding bool) ParseOpt {
	return func(opts *parseOpts) {
		opts.ignoreClaimsMapDecoding = ignoreClaimsMapDecoding
	}
}

func WithSignatureVerifier(signatureVerifier docjose.SignatureVerifier) ParseOpt {
	return func(opts *parseOpts) {
		opts.sigVerifier = signatureVerifier
	}
}

type JSONWebToken struct {
	Headers docjose.Headers
	Payload map[string]interface{}
	jws     *docjose.JSONWebSignature
}

func (j *JSONWebToken) Serialize(detached bool) (string, error) {
	if j.jws == nil {
		return "", errors.New("JWS serialization is supported only")
	}

	return j.jws.SerializeCompact(detached)
}

func (j *JSONWebToken) DecodeClaims(c interface{}) error {
	pBytes, err := json.Marshal(j.Payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	return json.Unmarshal(pBytes, c)
}

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() docjose.Headers {
	return map[string]interface{}{
		docjose.HeaderAlgorithm: AlgorithmNone,
	}
}

func IsJWS(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] != ""
}

func IsJWTUnsecured(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] == ""
}

func isValidJSON(s string) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return false
	}

	var j map[string]interface{}
	err = json.Unmarshal(b, &j)

	return err == nil
}

// NewSigned 构建一个签名的 JWT 对象
func NewSigned(claims interface{}, headers docjose.Headers, signer docjose.Signer) (*JSONWebToken, error) {
	return newSigned(claims, headers, signer)
}

func NewUnsecured(claims interface{}, headers docjose.Headers) (*JSONWebToken, error) {
	return newSigned(claims, headers, &unsecuredJWTSigner{})
}

func newSigned(claims interface{}, headers docjose.Headers, signer docjose.Signer) (*JSONWebToken, error) {
	payloadMap, err := PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("unmarshallable claims: %w", err)
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWT claims: %w", err)
	}

	jws, err := docjose.NewJWS(headers, nil, payloadBytes, signer)
	if err != nil {
		return nil, fmt.Errorf("create JWS: %w", err)
	}

	return &JSONWebToken{
		Headers: jws.ProtectedHeaders,
		Payload: payloadMap,
		jws:     jws,
	}, nil
}

func PayloadToMap(i interface{}) (map[string]interface{}, error) {
	if reflect.ValueOf(i).Kind() == reflect.Map {
		return i.(map[string]interface{}), nil
	}

	var (
		b   []byte
		err error
	)

	switch cv := i.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(i)
		if err != nil {
			return nil, fmt.Errorf("marshal interface[%T]: %w", i, err)
		}
	}

	var m map[string]interface{}

	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()

	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("convert to map: %w", err)
	}

	return m, nil
}

func Parse(jwtSerialized string, opts ...ParseOpt) (*JSONWebToken, []byte, error) {
	if !docjose.IsCompactJWS(jwtSerialized) {
		return nil, nil, errors.New("JWT of compacted JWS form is supported only")
	}

	pOpts := &parseOpts{}
	for _, opt := range opts {
		opt(pOpts)
	}

	return parseJWS(jwtSerialized, pOpts)
}

func parseJWS(jwtSerialized string, pOpts *parseOpts) (*JSONWebToken, []byte, error) {
	jwsOpts := make([]docjose.JWSParseOpt, 0)

	if pOpts.detachedPayload != nil {
		jwsOpts = append(jwsOpts, docjose.WithJWSDetachedPayload(pOpts.detachedPayload))
	}

	jws, err := docjose.ParseJWS(jwtSerialized, pOpts.sigVerifier, jwsOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("parse JWT from compact JWS: %w", err)
	}

	return mapJWSToJWT(jws, pOpts)
}

func mapJWSToJWT(jws *docjose.JSONWebSignature, pOpts *parseOpts) (*JSONWebToken, []byte, error) {
	headers := jws.ProtectedHeaders

	err := checkHeaders(headers)
	if err != nil {
		return nil, nil, fmt.Errorf("check JWT headers: %w", err)
	}

	token := &JSONWebToken{
		Headers: headers,
		jws:     jws,
	}

	if !pOpts.ignoreClaimsMapDecoding {
		claims, err := PayloadToMap(jws.Payload)
		if err != nil {
			return nil, nil, fmt.Errorf("read JWT claims from JWS payload: %w", err)
		}

		token.Payload = claims
	}

	return token, jws.Payload, nil
}

func checkHeaders(headers map[string]interface{}) error {
	if _, ok := headers[docjose.HeaderAlgorithm]; !ok {
		return errors.New("alg header is not defined")
	}

	typ, ok := headers[docjose.HeaderType]
	if ok {
		if err := checkTypHeader(typ); err != nil {
			return err
		}
	}

	cty, ok := headers[docjose.HeaderContentType]
	if ok && cty == TypeJWT {
		return errors.New("nested JWT is not supported")
	}

	return nil
}

func checkTypHeader(typ interface{}) error {
	typStr, ok := typ.(string)
	if !ok {
		return errors.New("invalid typ header format")
	}

	chunks := strings.Split(typStr, "+")
	if len(chunks) > 1 {
		ending := strings.ToUpper(chunks[1])
		if ending != TypeJWT && ending != TypeSDJWT {
			return errors.New("invalid typ header")
		}
		return nil
	}

	if typStr != TypeJWT {
		return errors.New("typ is not JWT")
	}

	return nil
}

type signatureVerifierFunc func(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error

func (s signatureVerifierFunc) Verify(joseHeaders docjose.Headers, payload, signingInput, signature []byte) error {
	return s(joseHeaders, payload, signingInput, signature)
}

var _ docjose.SignatureVerifier = (signatureVerifierFunc)(nil)

func verifyUnsecuredJWT(joseHeaders docjose.Headers, _, _, signature []byte) error {
	alg, ok := joseHeaders.Algorithm()
	if !ok {
		return errors.New("alg is not defined")
	}

	if alg != AlgorithmNone {
		return errors.New("alg value is not `none`")
	}

	if len(signature) > 0 {
		return errors.New("not empty signature")
	}

	return nil
}

func UnsecuredJWTVerifier() docjose.SignatureVerifier {
	return signatureVerifierFunc(verifyUnsecuredJWT)
}
