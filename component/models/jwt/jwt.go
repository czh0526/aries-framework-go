package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"
	"reflect"
	"strings"
)

const (
	TypeJWT       = "JWT"
	TypeSDJWT     = "SD-JWT"
	AlgorithmNone = "none"
)

type JSONWebToken struct {
	Headers jose.Headers
	Payload map[string]interface{}
	jws     *jose.JSONWebSignature
}

func (j *JSONWebToken) Serialize(detached bool) (string, error) {
	if j.jws == nil {
		return "", errors.New("JWS serialization is supported only")
	}

	return j.jws.SerializeCompact(detached)
}

type unsecuredJWTSigner struct{}

func (s unsecuredJWTSigner) Sign(_ []byte) ([]byte, error) {
	return []byte(""), nil
}

func (s unsecuredJWTSigner) Headers() jose.Headers {
	return map[string]interface{}{
		jose.HeaderAlgorithm: AlgorithmNone,
	}
}

func IsJWS(s string) bool {
	parts := strings.Split(s, ".")

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] != ""
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
func NewSigned(claims interface{}, headers jose.Headers, signer jose.Signer) (*JSONWebToken, error) {
	return newSigned(claims, headers, signer)
}

func NewUnsecured(claims interface{}, headers jose.Headers) (*JSONWebToken, error) {
	return newSigned(claims, headers, &unsecuredJWTSigner{})
}

func newSigned(claims interface{}, headers jose.Headers, signer jose.Signer) (*JSONWebToken, error) {
	payloadMap, err := PayloadToMap(claims)
	if err != nil {
		return nil, fmt.Errorf("unmarshallable claims: %w", err)
	}

	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWT claims: %w", err)
	}

	jws, err := jose.NewJWS(headers, nil, payloadBytes, signer)
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
