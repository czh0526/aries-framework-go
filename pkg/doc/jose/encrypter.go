package jose

import aries_jose "github.com/czh0526/aries-framework-go/component/kmscrypto/doc/jose"

const (
	A256GCM      = aries_jose.EncAlg(A256GCMALG)
	XC20P        = aries_jose.EncAlg(XC20PALG)
	A128CBCHS256 = aries_jose.EncAlg(A128CBCHS256ALG)
	A192CBCHS384 = aries_jose.EncAlg(A192CBCHS384ALG)
	// A256CBCHS384 for A256CBC-HS384 (AES256-CBC+HMAC-SHA384) content encryption.
	A256CBCHS384 = aries_jose.EncAlg(A256CBCHS384ALG)
	// A256CBCHS512 for A256CBC-HS512 (AES256-CBC+HMAC-SHA512) content encryption.
	A256CBCHS512 = aries_jose.EncAlg(A256CBCHS512ALG)
)
