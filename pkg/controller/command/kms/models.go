package kms

type CreateKeySetRequest struct {
	KeyType string `json:"keyType,omitempty"`
}

type CreateKeySetResponse struct {
	KeyID     string `json:"keyID,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

type JSONWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}
