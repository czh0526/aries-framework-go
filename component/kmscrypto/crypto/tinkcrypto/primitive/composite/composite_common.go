package composite

type EncryptedData struct {
	Ciphertext []byte `json:"ciphertext,omitempty"`
	IV         []byte `json:"iv,omitempty"`
	Tag        []byte `json:"tag,omitempty"`
}
