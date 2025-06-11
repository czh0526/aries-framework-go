package subtle

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
	"math/big"
)

var errUnsupportedEncoding = errors.New("secp256k1: unsupported encoding")

func GetCurve(curve string) elliptic.Curve {
	switch curve {
	case secp256k1pb.BitcoinCurveType_SECP256K1.String():
		return btcec.S256()
	default:
		return nil
	}
}

func ValidateSecp256K1Params(hashAlg, curve, encoding string) error {
	switch encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER.String():
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363.String():
	default:
		return errUnsupportedEncoding
	}

	switch curve {
	case secp256k1pb.BitcoinCurveType_SECP256K1.String():
		if hashAlg != "SHA256" {
			return errors.New("secp256k1: invalid hash type, expect SHA-256")
		}
	default:
		return fmt.Errorf("unsupported curve: %s", curve)
	}

	return nil
}

type Secp256k1Signature struct {
	R, S *big.Int
}

func (sig *Secp256k1Signature) EncodeSecp256K1Signature(encoding string, curveName string) ([]byte, error) {
	var (
		enc []byte
		err error
	)

	switch encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363.String():
		enc, err = ieeeP1363Encode(sig, curveName)
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER.String():
		enc, err = asn1encode(sig)
	default:
		err = errUnsupportedEncoding
	}

	if err != nil {
		return nil, fmt.Errorf("secp256k1: can't convert signature to %s encoding: %w", encoding, err)
	}

	return enc, nil
}

func NewSecp256K1Signature(r, s *big.Int) *Secp256k1Signature {
	return &Secp256k1Signature{r, s}
}
