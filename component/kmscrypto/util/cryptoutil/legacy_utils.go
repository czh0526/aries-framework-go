package cryptoutil

import "golang.org/x/crypto/blake2b"

func Nonce(pub1, pub2 []byte) (*[NonceSize]byte, error) {
	var nonce [NonceSize]byte

	nonceWriter, err := blake2b.New(NonceSize, nil)
	if err != nil {
		return nil, err
	}

	_, err = nonceWriter.Write(pub1)
	if err != nil {
		return nil, err
	}

	_, err = nonceWriter.Write(pub2)
	if err != nil {
		return nil, err
	}

	nonceOut := nonceWriter.Sum(nil)
	copy(nonce[:], nonceOut)

	return &nonce, nil
}
