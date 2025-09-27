package jose

import "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"

const (
	A256GCMALG      = "A256GCM"
	XC20PALG        = "XC20P"
	A128CBCHS256ALG = "A128CBC-HS256"
	// A192CBCHS384ALG represents AES_192_CBC_HMAC_SHA_384 encryption algorithm value.
	A192CBCHS384ALG = "A192CBC-HS384"
	// A256CBCHS384ALG represents AES_256_CBC_HMAC_SHA_384 encryption algorithm value (not defined in JWA spec above).
	A256CBCHS384ALG = "A256CBC-HS384"
	// A256CBCHS512ALG represents AES_256_CBC_HMAC_SHA_512 encryption algorithm value.
	A256CBCHS512ALG = "A256CBC-HS512"
)

type Headers = jose.Headers
