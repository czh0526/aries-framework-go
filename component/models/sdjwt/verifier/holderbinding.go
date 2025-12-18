package verifier

import (
	"fmt"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
	"github.com/czh0526/aries-framework-go/component/models/util/maphelpers"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/mitchellh/mapstructure"
)

type holderBindingPayload struct {
	Nonce    string               `json:"nonce,omitempty"`
	Audience string               `json:"aud,omitempty"`
	IssuedAt *josejwt.NumericDate `json:"iat,omitempty"`
}

func verifyHolderBindingJWT(holderJWT *modeljwt.JSONWebToken, pOpts *parseOpts) error {
	var bindingPayload holderBindingPayload

	d, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:           &bindingPayload,
		TagName:          "json",
		Squash:           true,
		WeaklyTypedInput: true,
		DecodeHook:       maphelpers.JSONNumberToJwtNumericDate(),
	})
	if err != nil {
		return fmt.Errorf("mapstruct verifyHolder failed, err: %w", err)
	}

	if err = d.Decode(holderJWT.Payload); err != nil {
		return fmt.Errorf("mapstruct verifyHolder decode failed, err = %w", err)
	}

	if pOpts.expectedNonceForHolderVerification != "" &&
		pOpts.expectedNonceForHolderVerification != bindingPayload.Nonce {
		return fmt.Errorf("nonce value `%s` does not match expected nonce value `%s`",
			bindingPayload.Nonce, pOpts.expectedNonceForHolderVerification)
	}

	if pOpts.expectedAudienceForHolderVerification != "" &&
		pOpts.expectedAudienceForHolderVerification != bindingPayload.Audience {
		return fmt.Errorf("audience value `%s` does not match expected audience value `%s`",
			bindingPayload.Audience, pOpts.expectedAudienceForHolderVerification)
	}

	return nil
}
