package subtle

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	secp256k1pb "github.com/czh0526/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
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
