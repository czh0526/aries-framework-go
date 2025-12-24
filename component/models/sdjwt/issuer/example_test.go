package issuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	modeljwt "github.com/czh0526/aries-framework-go/component/models/jwt"
)

const (
	issuer                 = "https://example.com/issuer"
	expectedHashWithSpaces = "qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus"
	sampleSalt             = "3jqcb67z9wks08zwiK7EyQ"
)

func ExampleNew() {
	signer, _, err := setUp()
	if err != nil {
		fmt.Println("failed to set-up test: %w", err)
	}

	claims := map[string]interface{}{
		"last_name": "Smith",
		"address": map[string]interface{}{
			"street_address": "123 Main St",
			"country":        "US",
		},
	}

	token, err := New("https://example.com/issuer", claims, nil, signer,
		WithStructuredClaims(true),
		WithNonSelectivelyDisclosableClaims([]string{"address.country"}),
		WithSaltFunc(func() (string, error) { return sampleSalt, nil }),
	)
	if err != nil {
		fmt.Println("failed to issue SD-JWT: %w", err)
	}

	var decoded map[string]interface{}

	err = token.DecodeClaims(&decoded)
	if err != nil {
		fmt.Println("failed to decode SD-JWT claims: %w", err)
	}

	issuerClaimsJSON, err := marshalObj(decoded)
	if err != nil {
		fmt.Println("verifier failed to marshal verified claims: %w", err)
	}

	fmt.Print(issuerClaimsJSON)

	// Output:{
	//   "_sd": [
	//     "V9-Eiizd3iJpdlxojQuwps44Zba7z6R08S7rPCDg_wU"
	//   ],
	//   "_sd_alg": "sha-256",
	//   "address": {
	//     "_sd": [
	//       "tD1XVFffEo0KTGuvHn9UlXCBgt3vot5xAanqXMdvVMg"
	//     ],
	//     "country": "US"
	//   },
	//   "iss": "https://example.com/issuer"
	// }

}

func setUp() (*modeljwt.JoseED25519Signer, *modeljwt.JoseEd25519Verifier, error) {
	issuerPublicKey, issuerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	signer := modeljwt.NewEd25519Signer(issuerPrivateKey)
	verifier, err := modeljwt.NewEd25519Verifier(issuerPublicKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, verifier, nil
}

func marshalObj(obj interface{}) (string, error) {
	objBytes, err := json.Marshal(obj)
	if err != nil {
		fmt.Println("failed to marshal object: %w", err)
	}
	return prettyPrint(objBytes)
}
