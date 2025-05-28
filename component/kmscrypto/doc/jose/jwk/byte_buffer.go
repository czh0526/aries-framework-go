package jwk

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
)

type ByteBuffer struct {
	data []byte
}

func (b *ByteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string

	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	b.data = decoded
	return nil
}

func (b *ByteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.Base64())
}

func (b *ByteBuffer) Base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b *ByteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func NewBuffer(data []byte) *ByteBuffer {
	if data == nil {
		return nil
	}

	return &ByteBuffer{
		data: data,
	}
}

func NewFixedSizeBuffer(data []byte, length int) *ByteBuffer {
	if len(data) > length {
		panic("NewFixedSizeBuffer: invalid call to NewFixedSizeBuffer (len(data) > length")
	}

	pad := make([]byte, length-len(data))

	return NewBuffer(append(pad, data...))
}
