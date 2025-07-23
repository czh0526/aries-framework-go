package jose

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const (
	compactJWERequiredNumOfParts      = 5
	errCompactSerializationCommonText = "unable to compact serialize: "
)

var (
	errWrongNumberOfCompactJWEParts = errors.New("invalid compact JWE: it must have five parts")
)

type RecipientHeaders struct {
	Alg string          `json:"alg,omitempty"`
	APU string          `json:"apu,omitempty"`
	APV string          `json:"apv,omitempty"`
	IV  string          `json:"iv,omitempty"`
	Tag string          `json:"tag,omitempty"`
	KID string          `json:"kid,omitempty"`
	EPK json.RawMessage `json:"epk,omitempty"`
}

type Recipient struct {
	Header       *RecipientHeaders `json:"header,omitempty"`
	EncryptedKey string            `json:"encrypted_key,omitempty"`
}

type JSONWebEncryption struct {
	ProtectedHeaders   Headers
	OrigProtectedHdrs  string
	UnprotectedHeaders Headers
	Recipients         []*Recipient
	AAD                string
	IV                 string
	Ciphertext         string
	Tag                string
}

func Deserialize(serializedJWE string) (*JSONWebEncryption, error) {
	if strings.HasPrefix(serializedJWE, "{") {
		return deserializeFull(serializedJWE)
	}
	return deserializeCompact(serializedJWE)
}

func deserializeFull(serializedJWE string) (*JSONWebEncryption, error) {
	rawJWE := rawJSONWebEncryption{}

	err := json.Unmarshal([]byte(serializedJWE), &rawJWE)
	if err != nil {
		return nil, err
	}

	return deserializeFromRawJWE(&rawJWE)
}

func deserializeCompact(serializedJWE string) (*JSONWebEncryption, error) {
	parts := strings.Split(serializedJWE, ".")
	if len(parts) != compactJWERequiredNumOfParts {
		return nil, errWrongNumberOfCompactJWEParts
	}

	rawJWE := rawJSONWebEncryption{
		B64ProtectedHeaders:      parts[0],
		B64SingleRecipientEncKey: parts[1],
		B64IV:                    parts[2],
		B64Ciphertext:            parts[3],
		B64Tag:                   parts[4],
	}

	return deserializeFromRawJWE(&rawJWE)
}

func deserializeFromRawJWE(rawJWE *rawJSONWebEncryption) (*JSONWebEncryption, error) {
	protectedHeaders, unprotectedHeaders, err := deserializeAndDecodeHeaders(rawJWE)
	if err != nil {
		return nil, err
	}

	recipients, err := deserializeRecipients(rawJWE)
	if err != nil {
		return nil, err
	}

	aad, err := base64.RawURLEncoding.DecodeString(rawJWE.B64AAD)
	if err != nil {
		return nil, err
	}

	iv, err := base64.RawURLEncoding.DecodeString(rawJWE.B64IV)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(rawJWE.B64Ciphertext)
	if err != nil {
		return nil, err
	}

	tag, err := base64.RawURLEncoding.DecodeString(rawJWE.B64Tag)
	if err != nil {
		return nil, err
	}

	deserializedJWE := JSONWebEncryption{
		ProtectedHeaders:   *protectedHeaders,
		OrigProtectedHdrs:  rawJWE.B64ProtectedHeaders,
		UnprotectedHeaders: *unprotectedHeaders,
		Recipients:         recipients,
		AAD:                string(aad),
		IV:                 string(iv),
		Ciphertext:         string(ciphertext),
		Tag:                string(tag),
	}

	return &deserializedJWE, nil
}

func deserializeAndDecodeHeaders(rawJWE *rawJSONWebEncryption) (*Headers, *Headers, error) {
	protectedHeadersBytes, err := base64.RawURLEncoding.DecodeString(rawJWE.B64ProtectedHeaders)
	if err != nil {
		return nil, nil, err
	}

	var protectedHeaders Headers
	err = json.Unmarshal(protectedHeadersBytes, &protectedHeaders)
	if err != nil {
		return nil, nil, err
	}

	var unprotectedHeaders Headers
	if rawJWE.UnprotectedHeaders != nil {
		err = json.Unmarshal(rawJWE.UnprotectedHeaders, &unprotectedHeaders)
		if err != nil {
			return nil, nil, err
		}
	}

	return &protectedHeaders, &unprotectedHeaders, nil
}

func parseDeserializeRecipients(rawJWE *rawJSONWebEncryption) ([]*Recipient, error) {
	if rawJWE.Recipients != nil {
		var recipients []*Recipient
		err := json.Unmarshal(rawJWE.Recipients, &recipients)
		if err != nil {
			return nil, err
		}

		return recipients, nil
	}

	recipient := &Recipient{
		EncryptedKey: rawJWE.B64SingleRecipientEncKey,
	}

	if rawJWE.SingleRecipientHeader != nil {
		err := json.Unmarshal(rawJWE.SingleRecipientHeader, &recipient.Header)
		if err != nil {
			return nil, err
		}
	}

	return []*Recipient{recipient}, nil
}

func deserializeRecipients(rawJWE *rawJSONWebEncryption) ([]*Recipient, error) {
	recipients, err := parseDeserializeRecipients(rawJWE)
	if err != nil {
		return nil, err
	}

	for _, recipient := range recipients {
		decodedEncKey, err := base64.RawURLEncoding.DecodeString(recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		recipient.EncryptedKey = string(decodedEncKey)
	}

	return recipients, nil
}

type rawJSONWebEncryption struct {
	B64ProtectedHeaders      string          `json:"protected,omitempty"`
	UnprotectedHeaders       json.RawMessage `json:"unprotected,omitempty"`
	Recipients               json.RawMessage `json:"recipients,omitempty"`
	B64SingleRecipientEncKey string          `json:"encrypted_key,omitempty"`
	SingleRecipientHeader    json.RawMessage `json:"header,omitempty"`
	B64AAD                   string          `json:"aad,omitempty"`
	B64IV                    string          `json:"iv,omitempty"`
	B64Ciphertext            string          `json:"ciphertext,omitempty"`
	B64Tag                   string          `json:"tag,omitempty"`
}
