package crypto

type Crypto interface {
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
