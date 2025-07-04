package crypto

type Crypto interface {
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, []byte, error)

	Decrypt(cipher, aad, nonce []byte, kh interface{}) ([]byte, error)

	Sign(msg []byte, kh interface{}) ([]byte, error)

	Verify(signature, msg []byte, kh interface{}) error
}

type PublicKey struct {
	KID   string `json:"kid,omitempty"`
	X     []byte `json:"x,omitempty"`
	Y     []byte `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

type PrivateKey struct {
	PublicKey PublicKey `json:"pubKey,omitempty"`
	D         []byte    `json:"d,omitempty"`
}
