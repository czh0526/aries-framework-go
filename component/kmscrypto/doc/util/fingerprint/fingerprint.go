package fingerprint

import (
	"encoding/binary"
	"errors"
	"github.com/btcsuite/btcutil/base58"
)

const (
	// X25519PubKeyMultiCodec for Curve25519 public key in multicodec table.
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	X25519PubKeyMultiCodec = 0xec
	// ED25519PubKeyMultiCodec for Ed25519 public key in multicodec table.
	ED25519PubKeyMultiCodec = 0xed
	// BLS12381g2PubKeyMultiCodec for BLS12-381 G2 public key in multicodec table.
	BLS12381g2PubKeyMultiCodec = 0xeb
	// BLS12381g1g2PubKeyMultiCodec for BLS12-381 G1G2 public key in multicodec table.
	BLS12381g1g2PubKeyMultiCodec = 0xee
	// P256PubKeyMultiCodec for NIST P-256 public key in multicodec table.
	P256PubKeyMultiCodec = 0x1200
	// P384PubKeyMultiCodec for NIST P-384 public key in multicodec table.
	P384PubKeyMultiCodec = 0x1201
	// P521PubKeyMultiCodec for NIST P-521 public key in multicodec table.
	P521PubKeyMultiCodec = 0x1202

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48
)

func PubKeyFromFingerprint(fingerprint string) ([]byte, uint64, error) {
	const maxMultiCodecBytes = 9

	if len(fingerprint) < 2 || fingerprint[0] != 'z' {
		return nil, 0, errors.New("unknown key encoding")
	}

	mc := base58.Decode(fingerprint[1:])
	code, br := binary.Uvarint(mc)
	if br == 0 {
		return nil, 0, errors.New("unknown key encoding")
	}

	if br > maxMultiCodecBytes {
		return nil, 0, errors.New("code exceeds maximum size")
	}

	if code == BLS12381g1g2PubKeyMultiCodec {
		if len(mc[br+g1CompressedSize:]) != bls12381G2PublicKeyLen {
			return nil, 0, errors.New("invalid bbs + public key")
		}

		return mc[br+g1CompressedSize:], code, nil
	}

	return mc[br:], code, nil
}
