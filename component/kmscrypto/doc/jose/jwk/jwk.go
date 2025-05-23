package jwk

import "github.com/go-jose/go-jose/v3"

type JWK struct {
	jose.JSONWebKey

	Kty string
	Crv string
}
