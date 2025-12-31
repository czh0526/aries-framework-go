package kmssigner

import (
	spicrypto "github.com/czh0526/aries-framework-go/spi/crypto"
	spikms "github.com/czh0526/aries-framework-go/spi/kms"
	"strings"
)

const (
	p256Alg = "ES256"
	p384Alg = "ES384"
	p521Alg = "ES521"
	edAlg   = "EdDSA"
)

type KMSSigner struct {
	KeyType   spikms.KeyType
	KeyHandle interface{}
	Crypto    spicrypto.Crypto
	MultiMsg  bool
}

func (s *KMSSigner) Sign(data []byte) ([]byte, error) {
	if s.MultiMsg {
		return s.Crypto.SignMulti(s.textToLines(string(data)), s.KeyHandle)
	}

	v, err := s.Crypto.Sign(data, s.KeyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func (s *KMSSigner) Alg() string {
	return KeyTypeToJWA(s.KeyType)
}

func (s *KMSSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

func KeyTypeToJWA(keyType spikms.KeyType) string {
	switch keyType {
	case spikms.ECDSAP256TypeIEEEP1363, spikms.ECDSAP256TypeDER:
		return p256Alg
	case spikms.ECDSAP384TypeIEEEP1363, spikms.ECDSAP384TypeDER:
		return p384Alg
	case spikms.ECDSAP521TypeIEEEP1363, spikms.ECDSAP521TypeDER:
		return p521Alg
	case spikms.ED25519:
		return edAlg
	}
	return ""
}
