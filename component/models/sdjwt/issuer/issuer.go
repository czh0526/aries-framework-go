package issuer

import modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"

type SelectiveDisclosureJWT struct {
	SignedJWT   *modeljwt.JSONWebToken
	Disclosures []string
}
