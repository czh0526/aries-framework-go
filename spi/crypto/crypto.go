package crypto

type Crypto interface {
	Encrypt(msg, aad []byte, kh interface{}) ([]byte, error)
	Decrypt(cipher, aad []byte, kh interface{}) ([]byte, error)

	Sign(msg []byte, kh interface{}) ([]byte, error)
	Verify(signature, msg []byte, kh interface{}) error

	ComputeMAC(data []byte, kh interface{}) ([]byte, error)
	VerifyMAC(mac, data []byte, kh interface{}) error

	WrapKey(cek, apu, apv []byte, recPubKey *PublicKey, opts ...WrapKeyOpts) (*RecipientWrappedKey, error)
	UnwrapKey(recWK *RecipientWrappedKey, kh interface{}, opts ...WrapKeyOpts) ([]byte, error)
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

type RecipientWrappedKey struct {
	KID          string    `json:"kid,omitempty"`
	EncryptedCEK []byte    `json:"encryptedcek,omitempty"`
	EPK          PublicKey `json:"epk,omitempty"`
	Alg          string    `json:"alg,omitempty"`
	APU          []byte    `json:"apu,omitempty"`
	APV          []byte    `json:"apv,omitempty"`
}
